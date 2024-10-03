#!/bin/bash
#
# generate-sql-dump.sh
#
# Script to generate a crash dump manually
#
# Syntax:
#    generate-sql-dump.sh <pid> [dump_directory]
#
MSSQL_CONF_FILE=/var/opt/mssql/mssql.conf
mssql_conf=$MSSQL_CONF_FILE

source $(dirname $(realpath $0))/crash-support-functions.sh

print_usage()
{
    echo "Syntax: generate-sql-dump.sh <pid> [dump_directory]"
}

if [ -f $MSSQL_CONF_FILE ] ; then
    get_config_value_from_key "filelocation" "defaultdumpdir" defaultdumpdir
    get_config_value_from_key "filelocation" "errorlogfile" errorlogfile
fi

if [ -z "$defaultdumpdir" ] ; then
    defaultdumpdir="/var/opt/mssql/log"
fi

if [ -z "$errorlogfile" ] ; then
    errorlogfile="/var/opt/mssql/log/errorlog"
fi

if [ "$1" == "" ]; then
    print_usage
    exit 1
fi

# Command-line arguments
#
program_name=sqlservr
now=$(date +"%m_%d_%Y_%H_%M_%S")
pid=$1
program_dir=/opt/mssql/bin

if [ ! "$2" == "" ]; then
    dump_dir=$(realpath $2)
else
    dump_dir=$defaultdumpdir
fi
errorlog_filepath=$(dirname $(realpath $errorlogfile))
errorlog_filename=$(basename $errorlogfile)
core_prefix=manual_core
instance_id=$(cat /var/opt/mssql/.system/instance_id)
crash_id=$(cat /proc/sys/kernel/random/uuid)
no_kill=true

# Setup all the variables before calling mkdir.
#
setup_dump_environment

echo Capturing core dump and information...

mkdir -p $dump_dir $capture_dir $bin_dir $lib_dir $log_dir $etc_dir
cd $dump_dir

capture_system_info
capture_program_info
take_process_dump

# Capturing binaries needs to happen after dump because we
# discover module list during dump.
#
capture_program_binaries

compress_dump

# Make sure files and directories in dump directory
# are accessible by group owner as well as user owner.
#
chmod -R g+rX $dump_dir

exit 0
