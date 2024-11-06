# binlogparser
2023-02-27 : 我要写一个分析binlog二进制日志的程序玩玩， 用来统计长事务， 大事务等

2024-11-06 :  
usage: binlog_parser.py [-f LOGFILE] [-t GETTOP] [-sp START_POSITION] [-ep END_POSITION] [-sd START_DATETIME] [-ed END_DATETIME] [-h]

  
  
**binlog分析工具**，支持MySQL 5.6，MySQL 5.7，MySQL 8.0。v4版本的binlog日志。  
  
## 可选参数:  
  
- `-f LOGFILE, --file LOGFILE`  
  需要分析的binlog文件。  
  
- `-t GETTOP, --top GETTOP`  
  打印top n。  
  
- `-sp START_POSITION, --start-position START_POSITION`  
  开始位置。  
  
- `-ep END_POSITION, --end-position END_POSITION`  
  结束位置。  
  
- `-sd START_DATETIME, --start-datetime START_DATETIME`  
  开始时间。  
  
- `-ed END_DATETIME, --end-datetime END_DATETIME`  
  结束时间。  
  
- `-h, --help`  
  帮助信息。
