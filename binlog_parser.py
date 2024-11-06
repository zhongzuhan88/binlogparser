# -*- coding: utf-8 -*-

"""
	@author  : zuhan.zhong
	@mail    : zuhan.zhong@139.com
	@date    : 2023-02-21
	@version : v1.0
	@describe: binlog分析工具，协助判断是否有长事务，大事务，热点表等
"""

import os
import re
import sys
import time
import copy
import struct
import random
import logging
import argparse
import pandas as pd




logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BINLOG_FILE_HEADER = b'\xfebin' #binlog开头都是4字节的魔术数
BINLOG_EVENT_HEADER_LENGTH = 19
BINLOG_ANONYMOUS_UUID='00000000-0000-0000-0000-000000000000' #未启用gtid时，gtid event 里的uuid是0，使用固定值做统计分析
REPORT_TOP_N = 10



"""
binlog event类型， 
来源于 MySQL 5.7.32
"""

# 这个其实没有用到， 只有日志输出时方便打印类型 后续可删除
BINLOG_EVENT_TYPE_LIST = ["UNKNOWN_EVENT","START_EVENT_V3","QUERY_EVENT","STOP_EVENT","ROTATE_EVENT","INTVAR_EVENT","LOAD_EVENT","SLAVE_EVENT","CREATE_FILE_EVENT","APPEND_BLOCK_EVENT","EXEC_LOAD_EVENT","DELETE_FILE_EVENT","NEW_LOAD_EVENT","RAND_EVENT","USER_VAR_EVENT","FORMAT_DESCRIPTION_EVENT","XID_EVENT","BEGIN_LOAD_QUERY_EVENT","EXECUTE_LOAD_QUERY_EVENT","TABLE_MAP_EVENT","PRE_GA_WRITE_ROWS_EVENT","PRE_GA_UPDATE_ROWS_EVENT","PRE_GA_DELETE_ROWS_EVENT","WRITE_ROWS_EVENT_V1","UPDATE_ROWS_EVENT_V1","DELETE_ROWS_EVENT_V1","INCIDENT_EVENT","HEARTBEAT_LOG_EVENT","IGNORABLE_LOG_EVENT","ROWS_QUERY_LOG_EVENT","WRITE_ROWS_EVENT","UPDATE_ROWS_EVENT","DELETE_ROWS_EVENT","GTID_LOG_EVENT","ANONYMOUS_GTID_LOG_EVENT","PREVIOUS_GTIDS_LOG_EVENT","TRANSACTION_CONTEXT_EVENT","VIEW_CHANGE_EVENT","XA_PREPARE_LOG_EVENT"]



class BinlogEventType:
	UNKNOWN_EVENT = 0
	START_EVENT_V3 = 1
	QUERY_EVENT = 2
	STOP_EVENT = 3
	ROTATE_EVENT = 4
	INTVAR_EVENT = 5
	LOAD_EVENT = 6
	SLAVE_EVENT = 7
	CREATE_FILE_EVENT = 8
	APPEND_BLOCK_EVENT = 9
	EXEC_LOAD_EVENT = 10
	DELETE_FILE_EVENT = 11
	NEW_LOAD_EVENT = 12
	RAND_EVENT = 13
	USER_VAR_EVENT = 14
	FORMAT_DESCRIPTION_EVENT = 15
	XID_EVENT = 16
	BEGIN_LOAD_QUERY_EVENT = 17
	EXECUTE_LOAD_QUERY_EVENT = 18
	TABLE_MAP_EVENT = 19
	PRE_GA_WRITE_ROWS_EVENT = 20
	PRE_GA_UPDATE_ROWS_EVENT = 21
	PRE_GA_DELETE_ROWS_EVENT = 22
	WRITE_ROWS_EVENT_V1 = 23
	UPDATE_ROWS_EVENT_V1 = 24
	DELETE_ROWS_EVENT_V1 = 25
	INCIDENT_EVENT = 26
	HEARTBEAT_LOG_EVENT = 27
	IGNORABLE_LOG_EVENT = 28
	ROWS_QUERY_LOG_EVENT = 29
	WRITE_ROWS_EVENT = 30
	UPDATE_ROWS_EVENT = 31
	DELETE_ROWS_EVENT = 32
	GTID_LOG_EVENT = 33
	ANONYMOUS_GTID_LOG_EVENT = 34
	PREVIOUS_GTIDS_LOG_EVENT = 35
	TRANSACTION_CONTEXT_EVENT = 36
	VIEW_CHANGE_EVENT = 37
	XA_PREPARE_LOG_EVENT = 38


	
def size_pretty(value):
	"""
	单位转换
	"""
	units = ["B", "KB", "MB", "GB", "TB", "PB"]
	size = 1024.0
	for i in range(len(units)):
		if (value / size) < 1:
			return "%.2f%s" % (value, units[i])
		value = value / size



class ProgressBar:
	"""
	进度条呀
	"""
	def __init__(self, psize=0):
		self.current_step = -1
		self.last_step = -1
		self.psize = psize

	
	def pset(self, step):
		self.current_step = round((step/self.psize)*100,2)
		
		if self.current_step - self.last_step >= 0.3:
			print("\r[%6.2f%%][%-50s]\r" % (100 * (step) / self.psize, '>' * (50 * (step) // self.psize)), end='', flush=True)
			self.last_step = self.current_step
	
	
	def pend(self):
		print("[100.00%][>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]", flush=True)

	
	
class BinlogEventReader:
	def __init__(self, binlogfilehander):
		self.binlog_file_hander = binlogfilehander
	
	
	def read(self, length):
		return self.binlog_file_hander.read(length)
		

	def read_binlog_file_header(self):
		return self.binlog_file_hander.read(4)
	
	
	def seek(self, position):
		self.binlog_file_hander.seek(position, 0)
	
	
	def read_format_description_event(self):
		"""
		每个binlog的第一个event
		binlog_version: 2字节
		server_version: 50字节
		create_timestamp: 4字节，MySQL第一次启动时记录启动时候， 后续每个binlog的值都为0
		header_length: 1字节 event_header 的长度， 当前为19
		array_of_post_header: 39个字节， 描述每种event的post_header长度
		"""
		binlog_version, server_version, create_timestamp, header_length = struct.unpack('=H50sIB', self.read(57))
		return binlog_version, server_version.decode(), create_timestamp, header_length
	
	
	def read_binlog_event_header(self):
		"""
		event header： 固定大小19字节
		timestamp: 4字节时间戳
		type code: 1字节， binlog event类型
		server id: 4字节 生成binlog的实例server id
		event_len: 4字节 整个binlog event的长度
		end_log_p: 4字节 下一个event的其实位置
		flags: 2字节
		"""
		
		try:
			timestamp, type_code, server_id, event_len, end_log_p, flags = struct.unpack('=IBIIIH', self.read(BINLOG_EVENT_HEADER_LENGTH))
			return timestamp, type_code, server_id, event_len, end_log_p, flags
		except Exception as e:
			logging.debug(e)
			return None, None, None, None, None, None
		
		
	def read_gitd_log_event(self):
		"""
		gtid_event 全部是固定长度的， 没有变长部分, 全长42个字节
		flags: 1字节， 表示是否为行格式， 是则为 0x00  否则 0x01
		server_uuid: 16字节的 server_uuid， 去掉了横杆“—”的十六进制表示 
		gno: 8字节  gtid
		ts type: 1字节， 固定值02
		last_commit：   8字节  
		seq number: 8字节 
		"""
		
		gtid_event = struct.unpack('=B16sQBQQ', self.read(42))
		uuid=(gtid_event[1]).hex()
		uuid="-".join((uuid[0:8], uuid[8:12], uuid[12:16], uuid[16:20], uuid[20:]))
		gtid=gtid_event[2]

		return (uuid, gtid, gtid_event[0])

		
	def read_write_row_event(self):
		pass
	
	
	def read_table_map_event(self):
		"""
		行模式特有的event 用于映射table_id 和 实际访问的表
		table_id： 6字节 
		reserved:  2字节 保留字段
		db_length: 1字节 表示db_name的长度
		db_name: 数据库名字
		table_length: 1字节 表示table_name长度
		table_name: 表名字
		......
		"""
		self.read(8)
		db_length,  = struct.unpack('B', self.read(1))
		db_name, = struct.unpack('{}s'.format(db_length), self.read(db_length))
		table_length, = struct.unpack('1xB', self.read(2))
		table_name, = struct.unpack('{}s'.format(table_length), self.read(table_length))
		return db_name.decode(), table_name.decode()
		
	
	
class BinlogParser:
	def __init__(self, binlogfile):
		self.binlogfile =  open(binlogfile,'rb')
		self.binlogfilesize=os.stat(binlogfile).st_size
		self.myBinlogEventReader = BinlogEventReader(self.binlogfile)
		self.transactions = []
		self.events = []
		self.transaction_count = 0
		self.event_count = 0
		self.rbr_only = False
		self.binlog_start_time = 0
		self.binlog_end_time = 0
		
	
	
	def parser(self):
		assert (self.myBinlogEventReader.read_binlog_file_header() == BINLOG_FILE_HEADER), "{} 不是binlog文件或文件已损坏!"
		
		
		pb = ProgressBar(self.binlogfilesize)
		
		logger.info('开始解析binlog文件...')
		while True:
			timestamp, type_code, server_id, event_len, end_log_p, flags =  self.myBinlogEventReader.read_binlog_event_header()
			
			if type_code == None:
				pb.pend()
				logger.info('binlog文件解析完成.')
				logger.info("binlog大小: {}.".format(size_pretty(self.binlogfilesize)))
				logger.info("总事务数: {}.".format(self.transaction_count))
				logger.info("总语句数: {}.".format(self.event_count))
				break
			
			else:
				self.binlog_end_time = timestamp
				pb.pset(end_log_p)
				
				if type_code == BinlogEventType.FORMAT_DESCRIPTION_EVENT:
					global BINLOG_EVENT_HEADER_LENGTH
					binlog_version, server_version, create_timestamp, header_length = self.myBinlogEventReader.read_format_description_event()
					logger.info("server version: MySQL {}".format(server_version))
					logger.info("binary log version : {}".format(binlog_version))
					assert (binlog_version == 4), "仅支持binlog v4版本."
					BINLOG_EVENT_HEADER_LENGTH = header_length
					self.binlog_start_time = timestamp
				
				elif type_code in (BinlogEventType.GTID_LOG_EVENT, BinlogEventType.ANONYMOUS_GTID_LOG_EVENT):
					transaction_info = {
						"trx_gtid":"",
						"trx_start_time":"",
						"trx_end_time":"",
						"trx_start_pos":0,
						"trx_end_pos":0,
						"trx_duration":0,
						"trx_size":0,
						"trx_row_count":0
					}
					
					transaction_header = True
					self.rbr_only = False
					
					uuid, gtid, binlog_row_format = self.myBinlogEventReader.read_gitd_log_event()
					
					if type_code == BinlogEventType.ANONYMOUS_GTID_LOG_EVENT:
						uuid, gtid = BINLOG_ANONYMOUS_UUID, end_log_p - event_len
						
					"""
						用这个判断binlog_format有问题，在5.6上发现row格式的事务， rbr_only=on的， 未知原因
						目前暂时通过更新的事件前面是否有map_event判断是否行格式
					"""	
					#assert (binlog_row_format == 0), "仅支持row格式的binlog."
					#if binlog_row_format != 0:
						#logger.warning( "gtid {}:{} row format is not row; ".format(uuid, gtid) )
					
					transaction_info["trx_gtid"] = "{}:{}".format(uuid, gtid)
					transaction_info["trx_start_pos"] = end_log_p - event_len
					
					
				elif type_code == BinlogEventType.TABLE_MAP_EVENT:
					db_name, table_name = self.myBinlogEventReader.read_table_map_event()
					self.rbr_only = True
					#logger.info("{}.{}".format(db_name, table_name))
					
					
				elif type_code in (BinlogEventType.WRITE_ROWS_EVENT, BinlogEventType.WRITE_ROWS_EVENT_V1, BinlogEventType.UPDATE_ROWS_EVENT, BinlogEventType.UPDATE_ROWS_EVENT_V1, BinlogEventType.DELETE_ROWS_EVENT, BinlogEventType.DELETE_ROWS_EVENT_V1):
					
					assert (self.rbr_only), "仅支持row格式的binlog."
					
					if transaction_header:
						transaction_start_at = copy.deepcopy(timestamp)
						transaction_header = False
					transaction_info["trx_size"] += event_len
					transaction_info["trx_row_count"] +=1
					
					if type_code in (BinlogEventType.WRITE_ROWS_EVENT, BinlogEventType.WRITE_ROWS_EVENT_V1):
						event_type = "insert"
					elif type_code in (BinlogEventType.UPDATE_ROWS_EVENT, BinlogEventType.UPDATE_ROWS_EVENT_V1):
						event_type = "update"
					else:
						event_type = "delete"
					
					event_info = {"event_id":end_log_p - event_len, "table":"{}.{}".format(db_name, table_name), "table_short":"{}.{}".format(db_name, re.sub('_[0-9]+$', '_x', table_name)), "event_type":event_type, "event_len": event_len}
					if ((end_log_p >= args.start_position and end_log_p <= args.end_position) or ( args.start_position < args.end_position < 0)) and ((timestamp >= args.start_datetime and timestamp <= args.end_datetime) or ( args.start_datetime < args.end_datetime < 0)): 
						self.events.append(event_info)
					self.event_count +=1
					
					
					
				elif type_code == BinlogEventType.XID_EVENT:
					transaction_info["trx_start_time"] = copy.deepcopy(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(transaction_start_at)))
					transaction_info["trx_end_time"] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(timestamp))
					transaction_info["trx_end_pos"] = end_log_p
					transaction_info["trx_duration"] = timestamp - transaction_start_at
					if ((end_log_p >= args.start_position and end_log_p <= args.end_position) or ( args.start_position < args.end_position < 0)) and ((timestamp >= args.start_datetime and timestamp <= args.end_datetime) or ( args.start_datetime < args.end_datetime < 0)): 
						self.transactions.append(transaction_info)
					self.transaction_count +=1
				else:
					pass
					
				
				self.myBinlogEventReader.seek(end_log_p)
	
	
	def generate_report(self):
		logger.info('正在生成报表...')
		df_transactions = pd.DataFrame(self.transactions)[["trx_gtid","trx_start_time","trx_end_time", "trx_start_pos", "trx_end_pos", "trx_duration", "trx_size", "trx_row_count"]]
		df_events = pd.DataFrame(self.events)[["event_id","table","table_short", "event_type", "event_len"]]
		
		df_transactions.columns = ["gtid","start_time","end_time", "start_pos", "end_pos", "duration", "size", "rows"] 
		
		"""  
		需要的报表：
			--事务维度
				事务大小 top100 ， 分析是否存在大事务
				事务持续时间 top100 ， 分析是否存在长事务
				
			--表维度, 含分表合并统计
				event_len  top100:  比如 xx表所有增删改产生的binlog event大小， 分析热点表问题
				执行次数 top100
				
			--语句维度
				表维度的细化, 每个表分别统计增删改的大小
		
		"""
		
		
		#######################
		# transaction维度
		#######################
		
		###### 大事务
		print("")
		print("")
		print("大事务top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_trx_size_top = df_transactions.sort_values(by='size', ascending=False).head(REPORT_TOP_N)
		df_trx_size_top['size'] = [size_pretty(v) for v in df_trx_size_top['size']]

		print(df_trx_size_top.to_string(index=False))
		

		##### 长事务
		print("")
		print("")
		print("")
		print("")
		print("长事务top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_trx_duration_top = df_transactions.sort_values(by='duration', ascending=False).head(REPORT_TOP_N)
		df_trx_duration_top['size'] = [size_pretty(v) for v in df_trx_duration_top['size']]
		print(df_trx_duration_top.to_string(index=False))
		
		
		#######################
		# 表维度
		df_tb = df_events.groupby('table').agg({'event_len':['count', 'sum', 'mean']}).reset_index()
		df_tb.columns = ["table_name", "count", "size", "size_avg"]
		#######################

		##### 表维度 日志大小
		print("")
		print("")
		print("")
		print("")
		print("表维度 日志大小 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_tb_len = df_tb.sort_values(by='size', ascending=False).head(REPORT_TOP_N);
		df_tb_len["size_avg"] = df_tb_len["size_avg"].round(2)
		df_tb_len['size'] = [size_pretty(v) for v in df_tb_len['size']]
		print(df_tb_len.to_string(index=False))


		##### 表维度 更新次数
		print("")
		print("")
		print("")
		print("")
		print("表维度 更新次数 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_tb_count = df_tb.sort_values(by='count', ascending=False).head(REPORT_TOP_N);
		df_tb_count["size_avg"] = df_tb_count["size_avg"].round(2)
		df_tb_count['size'] = [size_pretty(v) for v in df_tb_count['size']]
		print(df_tb_count.to_string(index=False))
		

			
		#######################
		# 分表维度
		df_tb_short = df_events.groupby('table_short').agg({'event_len':['count', 'sum', 'mean']}).reset_index()
		df_tb_short.columns = ["table_name", "count", "size", "size_avg"]
		#######################
		
		##### (分表合并)表维度 日志大小 
		print("")
		print("")
		print("")
		print("")
		print("(分表合并)表维度 日志大小 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_tb_short_len = df_tb_short.sort_values(by='size', ascending=False).head(REPORT_TOP_N);
		df_tb_short_len["size_avg"] = df_tb_short_len["size_avg"].round(2)
		df_tb_short_len['size'] = [size_pretty(v) for v in df_tb_short_len['size']]
		print(df_tb_short_len.to_string(index=False))
			
			
		##### (分表合并)表维度 更新次数
		print("")
		print("")
		print("")
		print("")
		print("(分表合并)表维度 更新次数 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_tb_short_count = df_tb_short.sort_values(by='count', ascending=False).head(REPORT_TOP_N);
		df_tb_short_count["size_avg"] = df_tb_short_count["size_avg"].round(2)
		df_tb_short_count['size'] = [size_pretty(v) for v in df_tb_short_count['size']]
		print(df_tb_short_count.to_string(index=False))
			

		#######################
		# 表+操作 维度
		df_stmt = df_events.groupby(['table','event_type']).agg({'event_len':['count','sum', 'mean']}).reset_index()
		df_stmt.columns = ["table_name", "event_type","count", "size", "size_avg"]
		#######################
		
		##### 每表增删改 日志大小 
		print("")
		print("")
		print("")
		print("")
		print("每表增删改 日志大小 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_stmt_len = df_stmt.sort_values(by='size', ascending=False).head(REPORT_TOP_N);
		df_stmt_len["size_avg"] = df_stmt_len["size_avg"].round(2)
		df_stmt_len['size'] = [size_pretty(v) for v in df_stmt_len['size']]
		print(df_stmt_len.to_string(index=False))
		
	
		
		##### 每表增删改 次数 
		print("")
		print("")
		print("")
		print("")
		print("每表增删改 次数 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_stmt_count = df_stmt.sort_values(by='count', ascending=False).head(REPORT_TOP_N);
		df_stmt_count["size_avg"] = df_stmt_count["size_avg"].round(2)
		df_stmt_count['size'] = [size_pretty(v) for v in df_stmt_count['size']]
		print(df_stmt_count.to_string(index=False))
		
		
		#######################
		# 分表+操作 维度
		df_short_stmt = df_events.groupby(['table_short','event_type']).agg({'event_len':['count','sum', 'mean']}).reset_index()
		df_short_stmt.columns = ["table_name", "event_type","count", "size", "size_avg"]
		#######################
		
		##### (分表合并)每表增删改 日志大小 
		print("")
		print("")
		print("")
		print("")
		print("(分表合并)每表增删改 日志大小 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_short_stmt_size = df_short_stmt.sort_values(by='size', ascending=False).head(REPORT_TOP_N);
		df_short_stmt_size["size_avg"] = df_short_stmt_size["size_avg"].round(2)
		df_short_stmt_size['size'] = [size_pretty(v) for v in df_short_stmt_size['size']]
		print(df_short_stmt_size.to_string(index=False))
			
			
			
		##### 每表增删改 次数 
		print("")
		print("")
		print("")
		print("")
		print("(分表合并)每表增删改 次数 top{}".format(REPORT_TOP_N))
		print("_"*130)
		print("")
		df_short_stmt_count = df_short_stmt.sort_values(by='count', ascending=False).head(REPORT_TOP_N);
		df_short_stmt_count["size_avg"] = df_short_stmt_count["size_avg"].round(2)
		df_short_stmt_count['size'] = [size_pretty(v) for v in df_short_stmt_count['size']]
		print(df_short_stmt_count.to_string(index=False))
			
		
		print("")
		print("")
		time.sleep(1)
		logger.info("binlog 时间区间: [{}] <--> [{}] , 共 {}s".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.binlog_start_time)), 
																   time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(self.binlog_end_time)), 
																   self.binlog_end_time - self.binlog_start_time
																))
		logger.info("finished...")
		
		

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='binlog分析工具，支持MySQL 5.6， MySQL5.7， MySQL8.0.  v4版本的binlog日志', add_help=False)
	parser.add_argument('-f','--file', dest='logfile', type=str, help='需要分析的binlong文件', default='')
	parser.add_argument('-t', '--top', dest='gettop', type=int, help='打印top n', default=20)
	parser.add_argument('-sp', '--start-position', dest='start_position', type=int, help='开始位置', default=-2)
	parser.add_argument('-ep', '--end-position', dest='end_position', type=int, help='结束位置', default=-1)
	parser.add_argument('-sd', '--start-datetime', dest='start_datetime', type=int, help='开始时间', default=-2)
	parser.add_argument('-ed', '--end-datetime', dest='end_datetime', type=int, help='结束时间', default=-1)
	parser.add_argument('-h', '--help', dest='help', action='store_true', help='help information', default=False)

	sysargs = sys.argv[1:]
	args = parser.parse_args()


	
	if args.help or (False if sysargs else True):
		parser.print_help()
		sys.exit(1)
		
	
		
	REPORT_TOP_N = args.gettop
		
	assert (os.path.isfile(args.logfile)), "日志文件不存在: {}".format(args.logfile)
	assert (args.end_position > args.start_position), "end_position 必须大于 start_position"
		
	
	

	#args.logfile = '/data/3806/mysql-bin.000001'
	#logfile = 'mysql-bin.000557'
	
	parser = BinlogParser(args.logfile)
	parser.parser()
	parser.generate_report()
	
