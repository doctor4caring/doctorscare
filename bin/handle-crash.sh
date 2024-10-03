#!/bin/bash
#
# handle-crash.sh
#
# Script to handle crashes. This script is not meant to be called manually,
# see PalDumper-and-Breakpad.md for the various options to capture a dump.
#
# Syntax:
#    handle-crash.sh <program_name> <pid> <program_directory> <dump_directory> <errorlog_file_path> <instance_id> <crash_id> [--nokill] [<already_generated_dump>]
#

echo ""

source $(/usr/bin/dirname $(/usr/bin/realpath $0))/crash-support-functions.sh

detect_distribution

# Command-line arguments
#
program_name=$(/usr/bin/basename $1)
now=$(/bin/date +"%m_%d_%Y_%H_%M_%S")
pid=$2
program_dir=$(/usr/bin/realpath $3)
dump_dir=$(/usr/bin/realpath $4)

# Argument 5 will be empty if there is no override
# (filelocation.errorlogfile) in mssql-conf file.
#
if [ ! -z $5 ]; then
    errorlog_filepath=$(/usr/bin/dirname $(/usr/bin/realpath $5))
    errorlog_filename=$(/usr/bin/basename $5)
fi

instance_id=$6
crash_id=$7

action=${PAL_ON_CRASH:-dump}

# Determine which actions need to be taken
#
do_dump=false
do_compress=false
do_attach=false

if [[ $action == *"dump"* ]]; then
    do_dump=true
fi

if [ "$action" == "dump_compress_attach" ] || [ "$action" == "dump" ]; then
    do_compress=true
fi

if [[ $action == *"attach"* ]]; then
    do_attach=true
fi


# Check if --nokill is specified otherwise try to kill child process if we exit prematurely
#
if [ ! -z $8 ] && [ $8 == '--nokill' ]; then
    no_kill=true
else
    trap "kill -9 $pid >& /dev/null" SIGINT SIGTERM SIGHUP SIGQUIT EXIT
    no_kill=false
fi

if [ -n "$9" ]; then
    pre_captured_dump_file=$9
fi

setup_dump_environment

# Attach debugger immediately if action is "debug"
#
if [ "$action" == "debug" ]; then
    $program_dir/attach-debugger.sh $program_dir/$program_name $pid
fi

# Take dump and capture files if action begins with "dump"
#
if [ "$do_dump" == "true" ]; then
    echo Capturing core dump and information to $dump_dir...

    /bin/mkdir -p $dump_dir $capture_dir $bin_dir $lib_dir $log_dir $etc_dir
    cd $dump_dir

    capture_system_info
    capture_program_info

    if [ -z "$pre_captured_dump_file" ]; then
        take_process_dump
    else
        echo "Dump already generated: $pre_captured_dump_file, moving to $dump_filename.gdmp"

        mv "$pre_captured_dump_file" "$dump_filename.gdmp"

        # See paldumper's ExecutePalDumper function where we force this file name convention
        # for the logs.
        #
        echo "Moving logs to $paldumper_debuglog_filename"
        mv "$pre_captured_dump_file.log" "$paldumper_debuglog_filename"
    fi

    # Capturing binaries needs to happen after dump because we
    # discover module list during dump.
    #
    capture_program_binaries

    # Convert the minidump to a core dump before compressing
    # because compressing will delete the original minidump
    #
    if [ "$do_attach" == "true" ]; then
        convert_minidump_to_core
    fi

    # Make sure files and directories in capture directory
    # are accessible by group owner as well as user owner.
    #
    chmod -R g+rX $dump_dir

    if [ "$do_compress" == "true" ]; then
        # Compression must be last (or at least last after everything that mutates files). 
        # We must not attempt to change anything in the dump bundle after this point, 
        # because the default behavior is to zip in the background, and any change we 
        # make will break the zipping operation. 
        # ie: (/bin/tar: dump.gdmp: file changed as we read it)
        #
        compress_dump
    fi

    # If dump_attach is set, we take a dump first and then attach to that.
    #
    if [ "$do_attach" == "true" ]; then
        $program_dir/attach-debugger.sh $program_dir/$program_name $pid $core_dump_filename
    fi
fi

if [ "$no_kill" == "true" ]; then
    # Let the caller know everything worked.
    #
    exit 0
else
    # This is a crash, let the caller know this is not a normal exit. The caller here 
    # is typically whoever launched SQL Server, because in the case of fatal crashes,
    # we re-use the entry process to invoke this script.
    #
    exit 1
fi
