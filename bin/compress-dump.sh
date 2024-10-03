#!/bin/bash

capture_dir=$1
target=$2
tempArchiveFile="${target}.work"

if [ "$capture_dir" = "" ]; then
    exit 1
fi

if hash pbzip2 2>/dev/null; then
    /bin/tar c -C $capture_dir . | pbzip2 > $tempArchiveFile
    returnVal=$?
else
    /bin/tar cjf $tempArchiveFile -C $capture_dir .
    returnVal=$?
fi

if [ $returnVal -ne 0 ]; then
    /bin/rm -f $tempArchiveFile

    # If it fails for any reason, export it at the expected location, except as a regular
    # directory instead of the expected archive. At least, the dump and other resources 
    # will still be found for investigation. This pattern with the ".d" suffix is 
    # recognized by the other tooling too.
    #
    /bin/mv $capture_dir $target.d
else
    /bin/mv $tempArchiveFile $target.tbz2
fi

/bin/rm -rf $capture_dir
