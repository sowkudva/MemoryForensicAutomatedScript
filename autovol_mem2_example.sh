  #! /bin/bash
#SDF Memory Forensics 2
# Script to autorun volatility plugins
echo "Memory Forensics volatility automation script"
echo ""
echo "Usage: Type autovol.sh <Memory image name> "

# Start of Autovol script
echo "****************************"
echo "*  volatility automation script has started  execution*"
echo "****************************"
echo ""
#
echo "Plugin results will be saved to the /results folder"
echo "Files extracted from memory will be saved to the /exports folder"
echo ""
# SETUP OPERATIONS
mkdir results
mkdir exports
mkdir malexports
res=results
exp=exports
mexp=malexports
echo ""
echo "Identiying the KDBG signature with imageinfo, results pending"
echo ""
date > $res/imageinfo_"$1"_.txt
#vol.py -f $1 imageinfo | tee -a $res/imageinfo_"$1"\_.txt
echo ""
#echo "Enter the KDBG signature to use for this memory image, example Win2008R2SP1"
#read kdbg
echo ""
kdbg=Win7SP1x64
echo "The operating system profile selected is :  --profile="$kdbg

# PART 1: PLUGINS TO FIND SUSPICIOUS PROCESSES
echo ""
echo "pslist plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg pslist > $res/pslist_$1\_.txt
echo ""
echo "pslist completed"
echo ""
#
echo ""
echo "psscan plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg psscan  1>$res/psscan_$1\_.txt
echo ""
echo "psscan completed"
echo ""
#
echo ""
echo "pstree plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg pstree > $res/pstree_$1\_.txt
echo ""
echo "pstree completed"
echo ""
#
echo ""
echo "psxview plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg psxview > $res/psxview_$1\_.txt
echo ""
echo "psxview completed"
echo ""
echo ""
#  POST PROCESSING LOGIC - part 1
echo ""
echo "Searching psxview results, results pending"
echo ""
grep -E -i "false" $res/psxview_$1\_.txt > $res/psxview_false_$1\_.txt
echo ""
echo "psxview search completed"
echo ""
echo ""

echo "Searching pslist results, results pending"
echo ""
grep -E -i "(system|wininit|lsass|lsaiso|lsm|services|sms|taskhost|winlogon|iexplore|explorer|svchost|csrss)" $res/pslist_$1\_.txt > $res/pslist_windowscore_$1\_.txt
grep -E -i -v "(system|wininit|lsass|lsaiso|lsm|services|sms|taskhost|winlogon|iexplore|explorer|svchost|csrss)" $res/pslist_$1\_.txt > $res/pslist_exclude_windows_core_$1\_.txt
echo "pslist search completed"
echo ""

#Analysing malicious process
echo ""
echo "malfind plugin running, results pending"
echo ""
vol.py -f $1 --profile=$kdbg malfind > $res/malfind_$1\_.txt
echo ""
echo "malfind completed"
echo ""
#
echo ""
echo "Using malfind to extract possible executables inside processes, results pending"
echo ""
vol.py -f $1 --profile=$kdbg malfind -D $mexp
file $mexp/* > $res/malfind_file_check_$1\_.txt
echo ""
echo "Malfind \export completed"
echo ""
echo ""
#
echo "Dumping the all process executables using procdump plugin"
echo ""
vol.py -f $1 --profile=$kdbg procdump -D  $exp
echo ""
echo "dump process completed"
echo ""
echo "Scanning all the executable files which are malicious using inbuilt clam scanner"
cd $exp
clamscan | grep -v ":OK"
echo ""
echo "Scanning completed for suspicious files"
echo ""
echo ""
sha256sum $exp/* > $res/256Hash_exports_$1\_.txt
cut -d " " -f1 $res/256Hash_exports_$1\_.txt > $res/256hash_exports_just_hash_$1\_.txt
echo "hash generation completed"

echo "autovol script has completed"
