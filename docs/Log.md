# Log

This project includes the following two types of log implementations:

- Use a mature logging library. current use [log4cplus](https://github.com/log4cplus/log4cplus)
- The project is implemented on its own [Discarded]

See: [Discussions](https://github.com/coturn/coturn/issues/1344)

## Setup log4cplus

- System distribution
  - Ubuntu

        sudo apt install liblog4cplus-dev 

- Install from source code
  - Download [source code](https://github.com/log4cplus/log4cplus)

        git clone https://github.com/log4cplus/log4cplus.git
  
  - Compile. See: https://github.com/log4cplus/log4cplus
  
        cd log4cplus
        mkdir build
        cd build
        cmake ..
        cmake --build . --traget install

## Usage

### Interface

- TURN_LOG_CATEGORY(category, level, ...)
- TURN_LOG_FUNC(level, ...) : Discarded, please use TURN_LOG_CATEGORY

### Log4cplus configure file

- Appender

|Appender                    |Description         |
|:--------------------------:|:------------------:|
|ConsoleAppender             |Ouput to console    |
|SysLogAppender              |Appends log events to a file. |
|NTEventLogAppender          |Appends log events to NT EventLog. Only windows|
|FileAppender                |Ouput to file       |
|RollingFileAppender         |Backup the log files when they reach a certain size|
|DailyRollingFileAppender	 |The log file is rolled over at a user chosen frequency|
|TimeBasedRollingFileAppender|The log file is rolled over at a user chosen frequency while also keeping in check a total maximum number of produced files. |
|SocketAppender              |Output to a remote a log server.|
|Log4jUdpAppender            |Sends log events as Log4j XML to a remote a log server. |
|AsyncAppender               |                    |

- Layout

| Layout      | Description |
|:-----------:|:-----------:|
|SimpleLayout |Simple layout|
|TTCCLayout   | |
|PatternLayout|Pattern layout|

  - [PatternLayout](https://log4cplus.github.io/log4cplus/docs/log4cplus-2.1.0/doxygen/classlog4cplus_1_1PatternLayout.html#details)


The recognized conversion characters are

<table>
<tr>
<td>Conversion Character</td>
<td>Effect</td>
</tr>
<tr>
<td align=center><b>b</b></td>
<td>Used to output file name component of path name.
E.g. <tt>main.cxx</tt> from path <tt>../../main.cxx</tt>.</td>
</tr>
<tr>
<td align=center><b>c</b></td>

<td>Used to output the logger of the logging event. The
logger conversion specifier can be optionally followed by
<em>precision specifier</em>, that is a decimal constant in
brackets.
If a precision specifier is given, then only the corresponding
number of right most components of the logger name will be
printed. By default the logger name is printed in full.
For example, for the logger name "a.b.c" the pattern
<b>%c{2}</b> will output "b.c".

</td>
</tr>

<tr>
<td align=center><b>d</b></td>

<td>Used to output the date of the logging event in <b>UTC</b>.

The date conversion specifier may be followed by a <em>date format
specifier</em> enclosed between braces. For example, <b>%%d{%%H:%%M:%%s}</b>
or <b>%%d{%%d&nbsp;%%b&nbsp;%%Y&nbsp;%%H:%%M:%%s}</b>.  If no date format
specifier is given then <b>%%d{%%d&nbsp;%%m&nbsp;%%Y&nbsp;%%H:%%M:%%s}</b>
is assumed.

The Following format options are possible:
<ul>
<li>%%a -- Abbreviated weekday name</li>
<li>%%A -- Full weekday name</li>
<li>%%b -- Abbreviated month name</li>
<li>%%B -- Full month name</li>
<li>%%c -- Standard date and time string</li>
<li>%%d -- Day of month as a decimal(1-31)</li>
<li>%%H -- Hour(0-23)</li>
<li>%%I -- Hour(1-12)</li>
<li>%%j -- Day of year as a decimal(1-366)</li>
<li>%%m -- Month as decimal(1-12)</li>
<li>%%M -- Minute as decimal(0-59)</li>
<li>%%p -- Locale's equivalent of AM or PM</li>
<li>%%q -- milliseconds as decimal(0-999) -- <b>Log4CPLUS specific</b>
<li>%%Q -- fractional milliseconds as decimal(0-999.999) -- <b>Log4CPLUS specific</b>
<li>%%S -- Second as decimal(0-59)</li>
<li>%%U -- Week of year, Sunday being first day(0-53)</li>
<li>%%w -- Weekday as a decimal(0-6, Sunday being 0)</li>
<li>%%W -- Week of year, Monday being first day(0-53)</li>
<li>%%x -- Standard date string</li>
<li>%%X -- Standard time string</li>
<li>%%y -- Year in decimal without century(0-99)</li>
<li>%%Y -- Year including century as decimal</li>
<li>%%Z -- Time zone name</li>
<li>%% -- The percent sign</li>
</ul>

Lookup the documentation for the <code>strftime()</code> function
found in the <code>&lt;ctime&gt;</code> header for more information.
</td>
</tr>

<tr>
<td align=center><b>D</b></td>

<td>Used to output the date of the logging event in <b>local</b> time.

All of the above information applies.
</td>
</tr>

<tr>
<td align=center><b>E</b></td>

<td>Used to output the value of a given environment variable.  The
name of is supplied as an argument in brackets.  If the variable does
exist then empty string will be used.

For example, the pattern <b>%E{HOME}</b> will output the contents
of the HOME environment variable.
</td>
</tr>

<tr>
<td align=center><b>F</b></td>

<td>Used to output the file name where the logging request was
issued.

<b>NOTE</b> Unlike log4j, there is no performance penalty for
calling this method.</td>
</tr>

<tr>
<td align=center><b>h</b></td>

<td>Used to output the hostname of this system (as returned
by gethostname(2)).

<b>NOTE</b> The hostname is only retrieved once at
initialization.

</td>
</tr>

<tr>
<td align=center><b>H</b></td>

<td>Used to output the fully-qualified domain name of this
system (as returned by gethostbyname(2) for the hostname
returned by gethostname(2)).

<b>NOTE</b> The hostname is only retrieved once at
initialization.

</td>
</tr>

<tr>
<td align=center><b>l</b></td>

<td>Equivalent to using "%F:%L"

<b>NOTE:</b> Unlike log4j, there is no performance penalty for
calling this method.

</td>
</tr>

<tr>
<td align=center><b>L</b></td>

<td>Used to output the line number from where the logging request
was issued.

<b>NOTE:</b> Unlike log4j, there is no performance penalty for
calling this method.

</tr>

<tr>
<td align=center><b>m</b></td>
<td>Used to output the application supplied message associated with
the logging event.</td>
</tr>

<tr>
<td align=center><b>M</b></td>

<td>Used to output function name using
<code>__FUNCTION__</code> or similar macro.

<b>NOTE</b> The <code>__FUNCTION__</code> macro is not
standard but it is common extension provided by all compilers
(as of 2010). In case it is missing or in case this feature
is disabled using the
<code>LOG4CPLUS_DISABLE_FUNCTION_MACRO</code> macro, %M
expands to an empty string.</td>
</tr>

<tr>
<td align=center><b>n</b></td>

<td>Outputs the platform dependent line separator character or
characters.
</tr>

<tr>
<td align=center><b>p</b></td>
<td>Used to output the LogLevel of the logging event.</td>
</tr>

<tr>
<td align=center><b>r</b></td>
<td>Used to output miliseconds since program start
of the logging event.</td>
</tr>

<tr>
<td align=center><b>t</b></td>

<td>Used to output the thread ID of the thread that generated
the logging event. (This is either `pthread_t` value returned
by `pthread_self()` on POSIX platforms or thread ID returned
by `GetCurrentThreadId()` on Windows.)</td>
</tr>

<tr>
<td align=center><b>T</b></td>

<td>Used to output alternative name of the thread that generated the
logging event.</td>
</tr>

<tr>
<td align=center><b>i</b></td>

<td>Used to output the process ID of the process that generated the
logging event.</td>
</tr>

<tr>
<td align=center><b>x</b></td>

<td>Used to output the NDC (nested diagnostic context) associated
with the thread that generated the logging event.
</td>
</tr>

<tr>
<td align=center><b>X</b></td>

<td>Used to output the MDC (mapped diagnostic context)
associated with the thread that generated the logging
event. It takes optional key parameter. Without the key
paramter (%%X), it outputs the whole MDC map. With the key
(%%X{key}), it outputs just the key's value.
</td>
</tr>

<tr>
<td align=center><b>"%%"</b></td>
<td>The sequence "%%" outputs a single percent sign.
</td>
</tr>

</table>

### [Example](../examples/etc/log.conf)

- Default. don't use configure file
  
```
INFO - System cpu num is 4

INFO - System enable num is 4

WARN - Cannot find config file: turnserver.conf. Default and command-line settings will be used.

INFO - Coturn Version Coturn-4.6.2 'Gorst'

INFO - Max number of open files/sockets allowed for this process: 1048576

INFO - Due to the open files/sockets limitation, max supported number of TURN Sessions possible is: 524000 (approximately)
```

- Pattern=%m
  
```
System cpu num is 4
System enable num is 4
Cannot find config file: turnserver.conf. Default and command-line settings will be used.
Coturn Version Coturn-4.6.2 'Gorst'
Max number of open files/sockets allowed for this process: 1048576
Due to the open files/sockets limitation, max supported number of TURN Sessions possible is: 524000 (approximately)
```

- Pattern=[%t] %-5p - %m
  
```
[140497062541824] INFO  - System cpu num is 4
[140497062541824] INFO  - System enable num is 4
[140497062541824] WARN  - Cannot find config file: turnserver.conf. Default and command-line settings will be used.
[140497062541824] INFO  - Coturn Version Coturn-4.6.2 'Gorst'
[140497062541824] INFO  - Max number of open files/sockets allowed for this process: 1048576
[140497062541824] INFO  - Due to the open files/sockets limitation, max supported number of TURN Sessions possible is: 524000 (approximately)
```

- Pattern=%D{%Y-%m-%d %H:%M:%S,%Q} %l [%t] %-5p %c - %m
  
```
2023-12-19 16:47:27,453.057 src/apps/relay/mainrelay.c:2950 [139876171266560] INFO  root - System cpu num is 4
2023-12-19 16:47:27,453.088 src/apps/relay/mainrelay.c:2951 [139876171266560] INFO  root - System enable num is 4
2023-12-19 16:47:27,453.141 src/apps/relay/mainrelay.c:2446 [139876171266560] WARN  root - Cannot find config file: turnserver.conf. Default and command-line settings will be used.
2023-12-19 16:47:27,453.223 src/apps/relay/mainrelay.c:2695 [139876171266560] INFO  root - Coturn Version Coturn-4.6.2 'Gorst'
2023-12-19 16:47:27,453.228 src/apps/relay/mainrelay.c:2696 [139876171266560] INFO  root - Max number of open files/sockets allowed for this process: 1048576
2023-12-19 16:47:27,453.232 src/apps/relay/mainrelay.c:2704 [139876171266560] INFO  root - Due to the open files/sockets limitation, max supported number of TURN Sessions possible is: 524000 (approximately)
```
