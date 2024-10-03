#!/bin/bash
#
# crash-support-functions.sh
#
# Functions to support crash handling
#

# Timeout for a single file/system command collection to take place.
#
collectTimeoutSecs=45

# Detect the distrubtion name
# This is used to modify the behavior on specific platforms.
#
function detect_distribution()
{
    arch=$(uname -m)
    kernel=$(uname -r)
    if [ -n "$(command -v lsb_release)" ]; then
        distroname=$(lsb_release -s -d)
    elif [ -f "/etc/os-release" ]; then
        distroname=$(grep PRETTY_NAME /etc/os-release | sed 's/PRETTY_NAME=//g' | tr -d '="')
    elif [ -f "/etc/debian_version" ]; then
        distroname="Debian $(cat /etc/debian_version)"
    elif [ -f "/etc/redhat-release" ]; then
        distroname=$(cat /etc/redhat-release)
    else
        distroname="$(uname -s) $(uname -r)"
    fi

    echo "${distroname}"
}

#
# setup_dump_environment()
#
# Setup dump environment
#
function setup_dump_environment()
{
    if [ -z $core_prefix ]; then
        eval core_prefix=core
    fi

    eval bundle_filename_base=$dump_dir/$core_prefix.$program_name.$now.$pid
    eval capture_dir=$dump_dir/$core_prefix.$program_name.$pid.temp
    eval bin_dir=$capture_dir/bin
    eval lib_dir=$capture_dir/lib
    eval log_dir=$capture_dir/log
    eval etc_dir=$capture_dir/etc

    mssql_conf=$MSSQL_CONF_FILE
    if [ -z $MSSQL_CONF_FILE ]; then
        mssql_conf=/var/opt/mssql/mssql.conf
    fi

    eval application_config_filename=$mssql_conf
    eval crash_config_filename=$mssql_conf
    eval dump_filename=$capture_dir/core.$program_name.$pid
    eval core_dump_filename=$dump_dir/core.$program_name.$pid.core
    eval infolog_filename=$log_dir/info.log
    eval gdb_debuglog_filename=$log_dir/gdb-debug.log
    eval paldumper_debuglog_filename=$log_dir/paldumper-debug.log
    eval gdblog_filename=$log_dir/gdb.log
    eval dumpdate_filename=$etc_dir/dump_date.txt
    eval crashid_filename=$etc_dir/crash_id.txt
    eval instanceid_filename=$etc_dir/instance_id.txt
    eval version_filename=$etc_dir/version.txt
    eval minidump2core_log_filename=$log_dir/minidump2core.log
}

#
# load_dump_config()
#
# Load dump configuration settings
#
function load_dump_config()
{
    # CoreDump section removing spaces around key=value pairs
    #
    # By reading the values in the script mssql-conf can be
    # used to dynamically change the values without restart.
    #
    # Example: mssql-conf set coredumptype filtered
    #
    if [ -f $crash_config_filename ] ; then
        echo "Reading dump control values from $crash_config_filename" >> $infolog_filename
        echo ${crash_config_file}  >> $infolog_filename
        get_config_value_from_key "coredump" "captureminiandfull" captureminiandfull
        get_config_value_from_key "coredump" "coredumptype" coredumptype
    else
        echo "Dump control values set to default.  Behavior controlled with $crash_config_filename" >> $infolog_filename
    fi

    # Validate and set the dump type
    #
    if [ -z $coredumptype ] ; then
        eval paldumper_dump_type_str="miniplus"
    else
        eval paldumper_dump_type_str=$coredumptype

        case $coredumptype in
            "mini")
                ;;
            "filtered")
                ;;
            "full")
                ;;
            *)
                eval paldumper_dump_type_str="miniplus"
                ;;
        esac
    fi

    # Are we taking a mini dump only or mini and full dump
    #
    if [ -z $captureminiandfull ]; then
        eval dump_mini_and_full=false
    else
        if $captureminiandfull; then
            eval dump_mini_and_full=true
        else
            eval dump_mini_and_full=false
        fi
    fi

    echo "$(date) Paldumper mini dump type: $paldumper_dump_type_str" >> $infolog_filename
    echo "$(date) Capturing mini and full dump: $dump_mini_and_full" >> $infolog_filename
}

#
#
# compress_dump()
#
# Compress the dump and its files. By default, dumps are not compressed when within Docker.
# The reason we do not compress them in container mode is that it takes considerable time, 
# and we cannot dispatch that to the background, because as soon as this script exits, we 
# will be exiting the container's main program, and the whole container will vanish.
# For all other environments, we compress in the background by default, so that the 
# service is free to restart immediately, and the time it takes to zip the whole package 
# does not impact the service's overall uptime.
#
function compress_dump()
{
    local dockerCompress=${PAL_COMPRESS_DOCKER_DUMP:="false"}
    local compressSynchronous=${PAL_DUMP_WAITFOR_COMPRESSION:="false"}

    if [ -f /.dockerinfo ] || [ -f /.dockerinit ] || [ -f /.dockerenv ]; then
        local isDocker="true"
    fi

    if [ "$dockerCompress" == "false" ] && [ "$isDocker" == "true" ]; then
        local uncompressedDir="$bundle_filename_base.d"
        echo "$(date) Not compressing the dump files, moving instead to: $uncompressedDir"
        /bin/mv "$capture_dir" "$uncompressedDir"
    else
        echo "$(date) Compressing the dump files"

        if [ "$compressSynchronous" == "false" ]; then
            echo "Core dump and information are being compressed in the background. When"
            echo "complete, they can be found in the following location:"
            echo "  $bundle_filename_base.tbz2"

            nohup sh $program_dir/compress-dump.sh $capture_dir $bundle_filename_base > /dev/null 2>&1 3>&1 &
        else
            echo "Compressing core dump synchronously to the following location:"
            echo "  $bundle_filename_base.tbz2"

            nohup sh $program_dir/compress-dump.sh $capture_dir $bundle_filename_base > /dev/null 2>&1 3>&1
        fi
    fi
}

#
# take_gdb_dump()
#
# Take dump with GDB
#
function take_gdb_dump()
{
    echo "$(date) Attempting to capture a dump with gdb"

    gdbcommands_filename=$capture_dir/gdbcommands

    # Write the gdb commands in a file
    #
    /bin/cat > $gdbcommands_filename <<-EOF
    set pagination off
    set height 0
    set width 0
    attach $pid
    gcore $dump_filename
    set logging overwrite on
    set logging file $gdb_debuglog_filename
    set logging on
    echo === Process information ===\n
    info inferior 1
    echo \\n
    echo === Shared library information ===\n
    info sharedlibrary
    echo \\n
    echo === Thread stacks ===\n
    thread apply all bt
    echo \\n
    echo === Thread registers ===\n
    thread apply all info all-reg
    echo \\n
    set logging off
EOF

    if $no_kill; then
        echo "detach" >> $gdbcommands_filename
    else
        echo "kill inferior 1" >> $gdbcommands_filename
    fi

    echo "quit" >> $gdbcommands_filename

    /usr/bin/gdb --nx --batch -x $gdbcommands_filename >& $gdblog_filename

    /bin/grep -qi "Could not attach" $gdblog_filename

    if [ $? -eq 0 ]; then
        echo "WARNING: Unable to capture crash dump with GDB. You may need to"
        echo "allow ptrace debugging, enable the CAP_SYS_PTRACE capability, or"
        echo "run as root. See log in: $gdblog_filename"
    else
        echo "$(date) Captured a dump with gdb"
    fi

    /bin/rm -f $gdbcommands_filename
}

#
# take_paldumper_dump()
#
# Take dump with paldumper
#
function take_paldumper_dump()
{
    if $dump_mini_and_full; then
      dokill=-n
    elif $no_kill; then
       dokill=-n
    fi

    # We do not pass -r to resume so process stays stopped for additional capture
    # SIGCONT will take place later in the script
    #
    echo "$(date) Attempting to capture a dump with paldumper for pid $pid"
    $program_dir/paldumper $dokill -p $pid -d $paldumper_dump_type_str -o $dump_filename.gdmp > $paldumper_debuglog_filename 2>&1

    if [ $? -ne 0 ]; then
        fullfilename=`/usr/bin/realpath $paldumper_debuglog_filename`
        echo "WARNING: Capture attempt failure detected"

        # If we failed miniplus try filtered and then gdb
        #
        if [ "miniplus" == $paldumper_dump_type_str ]; then
            echo "Attempting to capture a filtered dump with paldumper for pid $pid"
            $program_dir/paldumper $dokill -p $pid -d "filtered" -o $dump_filename.gdmp >> $paldumper_debuglog_filename 2>&1

            if [ $? -ne 0 ]; then
                echo "WARNING: Attempt to capture dump failed.  Reference $fullfilename for details"
                /bin/rm -f $dump_filename.gdmp
                dump_mini_and_full=true;
            else
                echo "Captured a filtered dump with paldumper"
            fi
        else
            echo "WARNING: Attempt to capture dump failed.  Reference $fullfilename for details"
            /bin/rm -f $dump_filename.gdmp
            dump_mini_and_full=true;
        fi
    else
        echo "Captured a dump with paldumper"
    fi

    # Take dump with gdb if mini and full dumps are requested; even if
    # paldumper failed (just in case).
    #
    if $dump_mini_and_full; then
        take_gdb_dump
    fi
}

#
# take_process_dump
#
# Take process dump
#
function take_process_dump()
{
    kill -SIGSTOP $pid

    load_dump_config

    if [ -e $program_dir/paldumper ]; then
        take_paldumper_dump
    else
        take_gdb_dump
    fi

    # Resume process if no kill was specified
    #
    if $no_kill ; then
        kill -SIGCONT $pid
    fi
}

#
# capture_program_info()
#
function capture_program_info()
{
    echo "$(date) Capturing program information"

    if [ -f $program_dir/$program_name ]; then
        PAL_PROGRAM_INFO=1 $program_dir/$program_name > $version_filename
    fi

    echo $instance_id > $instanceid_filename
    echo $crash_id > $crashid_filename

    err_schpattern="errorlog*"

    if [ ${#errorlog_filepath} -gt 2 ]; then
        sql_logs="$errorlog_filepath"

        # Error log file name could be different then default
        #
        err_schpattern="$errorlog_filename*"
    else
        if [ -f "${dump_dir}/log/errorlog" ]; then
            sql_logs="${dump_dir}/log"
        else
            if [ -f "${dump_dir}/errorlog" ]; then
                sql_logs="$dump_dir"
            else
                sql_logs="/var/opt/mssql/log"
            fi
        fi
    fi

    # Get Agent error log location
    #
    get_config_value_from_key "sqlagent" "errorlogfile" agentlog
    if [ -f "$agentlog" ] ; then

        # If we found valid file name then split file name and path.
        # as file name could be any name and not always sqlagent*
        #
        agentlog_filename=$(/usr/bin/basename $agentlog)
        agentlog=$(/usr/bin/dirname $agentlog)
        agentlog_schpattern="$agentlog_filename*"

    else
        agentlog=$sql_logs
        agentlog_schpattern="sqlagent*"
    fi

    copy_newest_n_files 8 "$sql_logs" "$err_schpattern" "$log_dir"
    copy_newest_n_files 8 "$agentlog" "$agentlog_schpattern" "$log_dir"
    copy_newest_n_files 1 "$sql_logs" "exception.log" "$log_dir"
    copy_newest_n_files 3 "$sql_logs" "SQLDu*.txt" "$log_dir"
    copy_newest_n_files 3 "$sql_logs" "SQLDu*.log" "$log_dir"
    copy_newest_n_files 3 "$sql_logs" "SQLDu*.mdmp" "$log_dir"
    copy_newest_n_files 3 "$sql_logs" "SQLDu*.ddf" "$log_dir"
    copy_newest_n_files 3 "$sql_logs" "SQLDU*.log" "$log_dir"
    copy_newest_n_files 1 "$sql_logs" "system_health*" "$log_dir"

    # If defaultdumpdir set copy SQLD* files from there as well
    # Place in log subdir to avoid collisions with /var/opt/mssql/log files
    #
    if [ "$dump_dir" != "/var/opt/mssql/log" ]; then
        /bin/mkdir -p "$log_dir/log"
        copy_newest_n_files 1 "$dump_dir" "exception.log" "$log_dir/log"
        copy_newest_n_files 3 "$dump_dir" "SQLD*.txt" "$log_dir/log"
        copy_newest_n_files 3 "$dump_dir" "SQLD*.log" "$log_dir/log"
        copy_newest_n_files 3 "$dump_dir" "SQLD*.mdmp" "$log_dir/log"
        copy_newest_n_files 3 "$dump_dir" "SQLD*.ddf" "$log_dir/log"
        copy_newest_n_files 3 "$dump_dir" "SQLDU*.log" "$log_dir/log"
    fi

    echo "$(date) === Historical Crash Information ===" >> $infolog_filename

    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $dump_dir/*.crash.json >> $infolog_filename 2>&1
    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $dump_dir/*.crash.txt >> $infolog_filename 2>&1
    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $dump_dir/*core*.json >> $infolog_filename 2>&1
    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $dump_dir/*core*.txt >> $infolog_filename 2>&1
    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $sql_logs/*core*.json >> $infolog_filename 2>&1
    /usr/bin/timeout $collectTimeoutSecs /usr/bin/tail -n 1024 $sql_logs/*core*.txt >> $infolog_filename 2>&1

    # $now is set by caller script and never changes so it is stable along with the
    # crash_id to use for name matching.
    #
    [ -f $dump_dir/$crash_id.crash.json ] && /bin/mv $dump_dir/$crash_id.crash.json $dump_dir/core.$program_name.$now.$pid.json
    [ -f $dump_dir/$crash_id.crash.txt ] && /bin/mv $dump_dir/$crash_id.crash.txt $dump_dir/core.$program_name.$now.$pid.txt

    [ -f $dump_dir/core.$program_name.$now.$pid.json ] && /bin/cp $dump_dir/core.$program_name.$now.$pid.json $capture_dir/crash.json
    [ -f $dump_dir/core.$program_name.$now.$pid.txt ] && /bin/cp $dump_dir/core.$program_name.$now.$pid.txt $capture_dir/crash.txt
}

#
# capture_program_binaries()
#
# Capture program binaries and associated libraries. This is implemented
# by reading the logs of paldumper / gdb.
#
function capture_program_binaries()
{
    echo "$(date) Capturing program binaries"

    # Capture program
    #
    /bin/cp $program_dir/$program_name $bin_dir

    # Capture libraries loaded by the target. The "BEGIN/END IMAGE LIST" is generated 
    # during the execution of paldumper, which is a prerequisite before calling this
    # capture_program_binaries function.
    #
    if [ -e $gdb_debuglog_filename ]; then
        list=`/bin/cat $gdb_debuglog_filename | /bin/grep -B1000 '=== Thread stacks' | /bin/grep -A1000 '=== Shared library' |  /usr/bin/awk '/\/.*/ { print $NF }'`
    else
        list=`/bin/cat $paldumper_debuglog_filename | /bin/grep -B1000 'END IMAGE LIST' | /bin/grep -A1000 'BEGIN IMAGE LIST' | /usr/bin/awk '/^\/.*/ { print $1 }'`
    fi

    for file in $list
    do
        dir=$lib_dir`/usr/bin/dirname $file`
        /bin/mkdir -p $dir
        /bin/cp $file $dir 2>/dev/null
    done

    # See if there is libthread in /lib
    #
    list=`/usr/bin/find /usr /lib -type f -name '*libthread*' -print -readable`
    for file in $list
    do
        dir=$lib_dir`/usr/bin/dirname $file`
        /bin/mkdir -p $dir
        /bin/cp $file $dir 2>/dev/null
    done
}

#
# capture_system_info_command()
#
# Capture system information from a command
#
# Arguments:
#   1. Title
#   2. Command
#
function capture_system_info_command()
{
    title=$1
    command="/usr/bin/timeout $collectTimeoutSecs $2"
    echo "$(date) === $title ===" >> $infolog_filename
    eval "$2 2>&1" >> $infolog_filename
    echo "" >> $infolog_filename
}

#
# capture_vma_info()
#
# Capture VMA regions used vs limit and warn is necessary
#
function capture_vma_info()
{
    echo "$(date) === VMA Information ===" >> $infolog_filename

    vmaCount="$(/bin/cat /proc/$pid/maps | /usr/bin/wc -l)"
    vmaLimit="$(/bin/cat /proc/sys/vm/max_map_count)"
    vmaPercentUsed=$(((100*$vmaCount)/$vmaLimit))

    echo "VMA Count: $vmaCount VMA Limit: $vmaLimit Percent VMA Used: $vmaPercentUsed" >> $infolog_filename

    if [ $vmaPercentUsed -gt 89 ]; then
        echo "=====================================================================" >> $infolog_filename
        echo "!!! WARNING - THE PROCESS IS NEARING OR HAS REACHED THE VMA LIMIT !!!" >> $infolog_filename
        echo "=====================================================================" >> $infolog_filename

        warningFile=$infolog_filename.VMA_WARNING
        echo "=====================================================================" >> $warningFile
        echo "!!! WARNING - THE PROCESS IS NEARING OR HAS REACHED THE VMA LIMIT !!!" >> $warningFile
        echo "!!! Reference $infolog_filename for details" >> $warningFile
        echo "=====================================================================" >> $warningFile
        echo "VMA Count: $vmaCount VMA Limit: $vmaLimit Percent VMA Used: $vmaPercentUsed" >> $warningFile
    fi

    echo "" >> $infolog_filename

    echo "=== Additional sysctl vm.* settings ===" >> $infolog_filename
    echo "" >> $infolog_filename
    sysctl -a 2>&1 | grep ^vm >> $infolog_filename
    echo "" >> $infolog_filename
}

#
# capture_system_info()
#
# Capture system information -- e.g. dmesg output, systemd logs, system configuration, etc...
#
function capture_system_info()
{
    # Capture basic system information
    #
    capture_system_info_command "Kernel Version" "uname -srvimp"
    capture_system_info_command "OS release" "cat /etc/os-release"
    capture_system_info_command "System memory information" "cat /proc/meminfo"
    capture_system_info_command "Control Group memory limit" "cat /sys/fs/cgroup/memory/memory.limit_in_bytes"
    capture_system_info_command "Command line" "cat /proc/$pid/cmdline"
    capture_system_info_command "Start Time" "stat /proc/$pid"
    capture_vma_info
    capture_system_info_command "Process limits" "cat /proc/$pid/limits"
    capture_system_info_command "Processor topology" "cat /proc/cpuinfo"
    capture_system_info_command "Process mounts" "cat /proc/$pid/mountinfo"
    capture_system_info_command "Process statistics" "cat /proc/$pid/stat"
    capture_system_info_command "Process status" "cat /proc/$pid/status"
    capture_system_info_command "Process memory maps" "cat /proc/$pid/maps"
    capture_system_info_command "Process memory maps (detailed)" "cat /proc/$pid/smaps"
    capture_system_info_command "Core Dump filter" "cat /proc/$pid/coredump_filter"
    capture_system_info_command "Process CGroup information" "cat /proc/$pid/cgroup"
    capture_system_info_command "Process scheduler information" "cat /proc/$pid/sched"
    capture_system_info_command "Process list" "ps aux"

    capture_system_info_command "Process handle information" "hash lsof && lsof -p $pid -O -o"

    capture_system_info_command "Process environment variables" "cat /proc/$pid/environ | tr '\0' '\n' | grep -v 'PASSWORD'"

    [ -f ${application_config_filename} ] && capture_system_info_command "Current application configuration" 'cat ${application_config_filename}'
    
    if hash "yum" 2>/dev/null; then
        capture_system_info_command "System package list (yum)" "yum list installed"
    elif hash dpkg; then
        capture_system_info_command "System package list (dpkg)" "dpkg -l"
    fi

    # Capture thread information
    #
    timeout $collectTimeoutSecs find /proc/$pid -type f | grep "/status$" > $log_dir/filelist.txt 2>&1
    timeout $collectTimeoutSecs find /proc/$pid -type f | grep "/io$" >> $log_dir/filelist.txt 2>&1
    timeout $collectTimeoutSecs find /proc/$pid -type f | grep "/stack$" >> $log_dir/filelist.txt 2>&1
    timeout $collectTimeoutSecs find /proc/$pid -type f | grep "/sched$" >> $log_dir/filelist.txt 2>&1
    timeout $collectTimeoutSecs cat $log_dir/filelist.txt | sort | xargs -rn1 cat -n >> $log_dir/thread_information.log 2>&1

    # Capture tail of system logs but make sure to grab enough for larger systems.
    #
    tailSize=20480
    timeout $collectTimeoutSecs dmesg --human --decode --ctime | tail -n$tailSize > $log_dir/dmesg.tail.txt
    timeout $collectTimeoutSecs journalctl --utc -a | tail -n$tailSize > $log_dir/journalctl.tail.txt
    timeout $collectTimeoutSecs journalctl --utc -a -u mssql-server > $log_dir/journalctl.sql.txt
    [ -f /var/log/syslog ] && timeout $collectTimeoutSecs tail -n$tailSize /var/log/syslog > $log_dir/syslog.tail.txt
    [ -f /var/log/messages ] && timeout $collectTimeoutSecs tail -n$tailSize /var/log/messages > $log_dir/messages.tail.txt
}

#
# copy_newest_n_files()
#
# Copy N newest files following pattern
#
# Arguments:
#   1. Number of files
#   2. Source directory
#   3. Source file pattern
#   4. Destination
#
function copy_newest_n_files()
{
    maxFiles=$1
    srcPattern=$2/$3
    dest=$4

    echo "$(date) Copying $srcPattern to $dest" >> $infolog_filename 2>&1

    filelistcount=$(/bin/ls -t $srcPattern 2>/dev/null | /usr/bin/head -n $maxFiles | /usr/bin/wc -l)
    filelist=$(/bin/ls -t $srcPattern 2>/dev/null | /usr/bin/head -n $maxFiles)

    if [ "$filelistcount" != "0" ]; then
        for file in $filelist; do
           /bin/cp $file $dest 2>/dev/null
        done
    fi
}


#
# get_config_value_from_key()
#
# Return the value of the key from conf file
#
# Arguments:
#   1. Section
#   2. Name of the Key
#   3. variable for the value to be returned
#
function get_config_value_from_key()
{
    local _section="$1"
    local _key="$2"

    # Use the Key in 2nd parameters
    #
    if [ -f $mssql_conf ] ; then
     local _val=$(/bin/sed -n "/^\s*\[$_section]\s*/I,/\s*\[/p" $mssql_conf | /bin/grep -i "^[ ]*$_key[ ]*=" | /bin/sed 's/ *= */=/g' | /bin/sed 's/./\L&/g')
    fi

    # Split Key and Value
    #
    local value=$(echo $_val |cut -d "=" -f 2)

    # Return value in parameter
    #
    eval "$3='$value'"
}

#
# convert_minidump_to_core()
#
# Converts the minidump to a core dump
#
function convert_minidump_to_core()
{
    echo "$(date) Converting minidump to core"

    # Convert the minidump to a core dump at $core_dump_filename
    #
    $program_dir/minidump-2-core -o $core_dump_filename $dump_filename.gdmp >> $minidump2core_log_filename 2>&1
}

