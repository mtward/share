#!/usr/bin/env bash
# File Name: scamp.sh
# Purpose: Download and install third party Clamav definition files.
# Version: 5.3a
# Sun, 19 December 2010 11:20:16 GMT
# Author: Gerard Seibert <gerard@seibercom.net>
SCRIPT_NAME="scamp"
VERSION="5.3a"

## =========================== Color escape codes =========================== ##
# If not running via CRON activate colored output.
if [[ -t 0 ]]; then
  txtblk='\e[0;30m' # Black - Regular
  txtblu='\e[0;34m' # Blue
  txtcyn='\e[0;36m' # Cyan
  txtgrn='\e[0;32m' # Green
  txtpur='\e[0;35m' # Purple
  txtred='\e[0;31m' # Red
  txtwht='\e[0;37m' # White
  txtylw='\e[0;33m' # Yellow
  bldblk='\e[1;30m' # Black - Bold
  bldblu='\e[1;34m' # Blue
  bldcyn='\e[1;36m' # Cyan
  bldgrn='\e[1;32m' # Green
  bldpur='\e[1;35m' # Purple
  bldred='\e[1;31m' # Red
  bldwht='\e[1;37m' # White
  bldylw='\e[1;33m' # Yellow
  unkblk='\e[4;30m' # Black - Underline
  undblu='\e[4;34m' # Blue
  undcyn='\e[4;36m' # Cyan
  undgrn='\e[4;32m' # Green
  undpur='\e[4;35m' # Purple
  undred='\e[4;31m' # Red
  undwht='\e[4;37m' # White
  undylw='\e[4;33m' # Yellow
  badgrn='\e[42m'   # Green
  bakblk='\e[40m'   # Black - Background
  bakblu='\e[44m'   # Blue
  bakcyn='\e[46m'   # Cyan
  bakpur='\e[45m'   # Purple
  bakred='\e[41m'   # Red
  bakwht='\e[47m'   # White
  bakylw='\e[43m'   # Yellow
  txtrst='\e[0m'    # Text Reset
fi

## ************************ DECLARE STATEMENTS *******************************##
# Declare statements - Should not be altered !
declare -a DIRLIST
declare -a LDB_A
declare -a MSRBL_A
declare -a SANE_A
declare -a SECURITE_A
declare -a WINNOW_1A
declare -a WINNOW_2A
declare -a WINNOW_3A
declare -a WINNOW_A
declare -a ZIPFILES
declare -i DIRLIST_COUNT
declare -i EDIT_CONFIG
declare -i FAILED
declare -i GET_LDB
declare -i GET_MALWARE
declare -i GET_MSRBL
declare -i GET_SANE
declare -i GET_SECURITE
declare -i GET_WINNOW
declare -i INSTALLED
declare -i IS_DIGIT
declare -i L_TYPE
declare -i LIMIT
declare -i MK_LOG
declare -i MSRBL_COUNT
declare -i NO_UPDATE
declare -i RELOAD
declare -i REST
declare -i RESTING
declare -i SYS_LOG
declare -i W_SUM
declare -i WPC
declare -i ZIPFILES_COUNT

## ======================== Definition file listing ========================= ##
# ldb files
LDB_A=(
spam.ldb
spam.ldb.sig
winnow.complex.patterns.ldb
winnow.complex.patterns.ldb.sig)

# MSRBL files (Inclusive)
MSRBL_A=(
MSRBL-Images.hdb
MSRBL-SPAM.ndb
MSRBL-SPAM-CR.ndb)

# Sanesecurity files  (Inclusive)
SANE_A=(
crdfam.clamav.hdb
crdfam.clamav.hdb.sig
doppelstern.hdb
doppelstern.hdb.sig
doppelstern.ndb
doppelstern.ndb.sig
INetMsg-SpamDomains-2m.ndb
INetMsg-SpamDomains-2m.ndb.sig
junk.ndb
junk.ndb.sig
jurlbl.ndb
jurlbl.ndb.sig
jurlbla.ndb
jurlbla.ndb.sig
lott.ndb
lott.ndb.sig
phish.ndb
phish.ndb.sig
rogue.hdb
rogue.hdb.sig
sanesecurity.ftm
sanesecurity.ftm.sig
scam.ndb
scam.ndb.sig
scamnailer.ndb
scamnailer.ndb.sig
sigwhitelist.ign2
sigwhitelist.ign2.sig
spamattach.hdb
spamattach.hdb.sig
spamimg.hdb
spamimg.hdb.sig
spear.ndb
spear.ndb.sig
spearl.ndb
spearl.ndb.sig)

# SecuriteInfo files (Inclusive)
SECURITE_A=(
honeynet.hdb
securiteinfo.hdb
securiteinfobat.hdb
securiteinfodos.hdb
securiteinfoelf.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb
securiteinfosh.hdb)

## All securite files
SECURITE_A[0]="honeynet.hdb
securiteinfo.hdb
securiteinfobat.hdb
securiteinfodos.hdb
securiteinfoelf.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb
securiteinfosh.hdb"

## Securite Windows Files
SECURITE_A[1]="securiteinfobat.hdb
securiteinfodos.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb"

##
SECURITE_A[2]="securiteinfoelf.hdb
securiteinfo.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb"

##
SECURITE_A[3]="securiteinfobat.hdb
securiteinfodos.hdb
securiteinfoelf.hdb
securiteinfooffice.hdb
securiteinfosh.hdb"

# Winnow files (Inclusive)
WINNOW_A=(
winnow.attachments.hdb
winnow.attachments.hdb.sig
winnow.complex.patterns.ldb
winnow.complex.patterns.ldb.sig
winnow_extended_malware.hdb
winnow_extended_malware.hdb.sig
winnow_extended_malware_links.ndb
winnow_extended_malware_links.ndb.sig
winnow_malware.hdb
winnow_malware.hdb.sig
winnow_malware_links.ndb
winnow_malware_links.ndb.sig
winnow_phish_complete.ndb
winnow_phish_complete.ndb.sig
winnow_phish_complete_url.ndb
winnow_phish_complete_url.ndb.sig
winnow_spam_complete.ndb
winnow_spam_complete.ndb.sig)

# Winnow files
# WPC = 1
W_FILES_1A=(
winnow.attachments.hdb
winnow.attachments.hdb.sig
winnow_extended_malware_links.ndb
winnow_extended_malware_links.ndb.sig
winnow_malware.hdb
winnow_malware.hdb.sig
winnow_malware_links.ndb
winnow_malware_links.ndb.sig
winnow_phish_complete_url.ndb
winnow_phish_complete_url.ndb.sig)

# wpc = 2
W_FILES_2A=(
winnow_phish_complete.ndb
winnow_phish_complete.ndb.sig
winnow_spam_complete.ndb
winnow_spam_complete.ndb.sig)

W_FILES_3A=(
winnow.attachments.hdb
winnow.attachments.hdb.sig
winnow_extended_malware.hdb
winnow_extended_malware.hdb.sig
winnow_extended_malware_links.ndb
winnow_extended_malware_links.ndb.sig
winnow_malware.hdb
winnow_malware.hdb.sig
winnow_malware_links.ndb
winnow_malware_links.ndb.sig
winnow_phish_complete.ndb
winnow_phish_complete.ndb.sig
winnow_spam_complete.ndb
winnow_spam_complete.ndb.sig)

## Path settings
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
# For tcsh or csh shells you may need to use this instead. Comment out above
# and uncomment this. Modify as required.
# set PATH = (/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

## ================================ DEFAULTS ================================ ##
# These are the default values for the program. They can be over written by
# using the [-c] option and creating a new config file

# You can set the location of the Clamav database here using the $CLAMAV_DB
# variable or you can set it using an environmental variable.
# By default, it is NULL -- you must set it in the config file. The config
# file setting will OVER-RIDE the setting here or in the environment.
# Place the exact PATH between the double quotation marks.

CLAMAV_DB=${CLAMAV_DB:-""}
CONFIG_DIR=${CONFIG_DIR:-"/etc/scamp"}
CONFIG_FILE=${CONFIG_FILE:-${CONFIG_DIR}/default}
C_GROUP=${C_GROUP:-"clamav"}
C_PID=${C_PID:-"/var/run/clamav/clamd.pid"}
C_USER=${C_USER:-"clamav"}
GET_LDB=${GET_LDB:-1}
GET_MALWARE=${GET_MALWARE:-1}
GET_MSRBL=${GET_MSRBL:-0}
GET_SANE=${GET_SANE:-1}
GET_SECURITE=${GET_SECURITE:-4}
GET_WINNOW=${GET_WINNOW:-1}
L_TYPE=${L_TYPE:-1}
MK_LOG=${MK_LOG:-0}
RELOAD=${RELOAD:-1}
REST=${REST:-1}
SYS_LOG=${SYS_LOG:-1}
WPC=${WPC:-1}
W_SUM=${W_SUM:-1}
## =============================== FUNCTIONS ================================ ##
## ============================== assign_value ============================== ##
# This simple function takes the preset value of a variable and compares it
# with the value imput by the user. If it is a new value, the old value is over
# written and the new value is placed in the 'config file'.

function assign_value ()
{
# Check to see how many variables were passed
# See if two were passed
if [[ ${#} -eq 2 ]]; then
  eval ${2}=\${1}
fi
}
## ======================== function bad_file_delete ======================== ##
# This function will delete a downloaded file that fails an integrity check.
# It is passed the name of the file. It attempts to delete it in all of the
# ${CLAMAV_DB} sub directories.

function bad_file_delete ()
{
for b in ${MW_DIR} ${SI_DIR} ${MSR_DIR} ${SANE_DB} ${T_DIR}
  do
    if [[ -d ${b} ]]; then
      if [[ -e ${b}/${1} ]]; then
        rm -f ${b}/${1}
      fi
    fi
  done
}
## ========================= function check_install ========================= ##
# This is the check_install function. It utilises clamscan to check the
# integrity of the newly downloaded definition files.

function check_install ()
{
# Switch to the tmp directory
cd ${T_DIR}

# Initialise the array counter
LIMIT=0
## Create an array of the files to be checked
for F in $(ls *.?db *.db *.ftm *.ign2 2>/dev/null)
do
  if [[ -e ${F} ]]
    then
    DIRLIST[$LIMIT]=${F}
    LIMIT=$(( LIMIT+1 ))
  fi
done

## Initialize variables and start checking the files.
DIRLIST_COUNT=${#DIRLIST[*]}
FAILED=0
INSTALLED=0
LIMIT=0
NO_UPDATE=0

## Create a temp file to test the definition files against
TEST_FILE=$(mktemp ${T_DIR}/NOT_A_VIRUS.XXXXXX)
printf "This is a test file for use by clamscan.
Clamscan checks this file when run from withing scamp.
It is safe to delete this file/n"> ${TEST_FILE}

while [ "${LIMIT}" -lt "${DIRLIST_COUNT}" ]
do
# Run clamscan to check the file integrity
  clamscan --quiet --no-summary -d ${DIRLIST[$LIMIT]} ${TEST_FILE} &>/dev/null
# Capture the exit code
  EC=$?
# Branch depending on the exit code.
  case ${EC} in
  [0]*)
# Clamscan did not report any errors.
# Now check to see if this is a newer signature file.
# cmp will respond with '0' if the files are identical.
# 1 if they are different.
# 2 if the file does not exist.
# We will trap the exit code in variable 'CEC'.
# We are using the 's' flag to slightly improve speed.
# Remove them for more detailed output
# First make sure the file is larger than 0
    if [ -s ${DIRLIST[$LIMIT]} ]; then
      cmp -s ${DIRLIST[$LIMIT]} ${CLAMAV_DB}/${DIRLIST[$LIMIT]}
      CEC=$?
    else
# The file has a 0 length -- bad
      CEC=9
    fi
  ;;
  *)
# Clamscan reported an error -- probably error 50.
# Therefore we will not attempt to install this file.
# The actual error code will be printed out in the event of a problem.
# The failed file will be erased.
# Comment out the line below beginning with 'rm' to save it.
# The variable $MVEC will be set to 'X' -- no-op
    printf "\n"
    printf "\t${txtred}********** WARNING **********${txtrst}\n"
    printf "\tUnable to install: %s\n" ${DIRLIST[$LIMIT]}
    printf "\tClamscan exited with error code %d\n" ${EC}
    printf "\tTry downloading and installing the file again.\n\n"
    FAILED=$((FAILED+1))
# Call bad_file_delete function and pass it the name of the failed file.
    bad_file_delete ${DIRLIST[$LIMIT]}
    MVEC="X"
    CEC=9
  ;;
  esac
# Process the cmp exit code
  case ${CEC} in
    [0]*)
# The files are identical
# Update the 'NO_UPDATE' counter.
# Delete the file
# The variable $MVEC will be set to 'X' -- no-op
      if [[ ${W_SUM} -gt 0 ]]; then
        printf "\t${bldwht}No update available ${txtrst}%s\n" ${DIRLIST[$LIMIT]}
      fi
      NO_UPDATE=$((NO_UPDATE+1))
# The files are identical, so delete the tmp one.
      rm -f ${DIRLIST[$LIMIT]}
# Initialise ${MVEC}  to "X" == for possible future use only.
      MVEC="X"
    ;;
    [1]*)
# The files are different
# We will install the file
# Trap the 'mv' exit code in 'MVEC'
      mv -f ${DIRLIST[$LIMIT]} ${CLAMAV_DB}/${DIRLIST[$LIMIT]}
# Trap the exit code
      MVEC=$?
    ;;
    [2]*)
# Error code 2 usually means that file(2) does not exist.
# We will attempt to install file(1).
# Trap the 'mv' exit code in 'MVEC'
      mv -f ${DIRLIST[$LIMIT]} ${CLAMAV_DB}/${DIRLIST[$LIMIT]}
# Trap the exit code
      MVEC=$?
    ;;
    [9]*)
# Bad news
# Something was wrong with the file. Probably 0 length
# It should have all ready been deleted by the "bad_file_delete" function.
      :
    ;;
    *)
# cmp encountered a problem.
# We will not try to install the file.
# The file should have all ready been erased by the "bad_file_delete" function
# The variable $MVEC will be set to 'X' -- no-op
# Incrementing the 'FAILED' counter
      printf "\tcmp issued error code %d\n" ${CEC}
      printf "\tUnable to update %s at this time\n" ${DIRLIST[$LIMIT]}
      printf "\tTry again later\n"
      MVEC="X"
      FAILED=$((FAILED+1))
    ;;
  esac
# Process the mv exit code
  case ${MVEC} in
    [0]*)
# Everything went well. The file installed correctly.
# Increment the 'INSTALLED' counter.
      if [[ ${W_SUM} -gt 0 ]]; then
        printf "\t${txtcyn}Installed:......... ${txtrst}%s\n" ${DIRLIST[$LIMIT]}
      fi
      INSTALLED=$((INSTALLED+1))
    ;;
    X*)
# Nothing happens here.
# For possible future use!
    :
    ;;
    *)
# OPPS, something went wrong.
# We are unable to install the file
# The file will be deleted
# Increment the 'FAILED' counter
      printf "\tmv issued error code %d\n" $MVEC
      printf "\tUnable to install at this time!\n"
      printf "\tPlease try again later\n"
# Increment the ${FAILED} counter.
      FAILED=$((FAILED+1))
    ;;
  esac
# Increment the 'LIMIT' counter.
  LIMIT=$((LIMIT+1))
# Clear the 'MVEC' flag -- set to NULL
  unset MVEC
done
}
## ========================= function clean_up_tmp ========================== ##
# The "clean_up_tmp" function is basically just a safety check. There should be
# no left over files in the tmp directory when the script exits.

function clean_up_tmp ()
{
# Remove any files that don't belong in tmp
cd ${T_DIR}
for F in $(ls *.?db *.db *.ftm *.gz *.ign2 NOT_A_VIRUS.* 2>/dev/null)
  do
    rm -f ${F}
  done
}
## ========================== function get_files =========================== ##
# This is the get_files function.

function get_files ()
{
# This is the "snooze" test. It will delay the start of a download session
# between 0 and 546 seconds (Roughly 9 minutes). It will only work when the
# script is run via CRON. The variable $REST activates this function.

# See if the variable 'REST' has been set or if forcing it from command line
# And if we are running via CRON
if [ ${REST} -gt 0 -a ! -t 0 ]; then
# Use the BASH RANDOM function to generate a random number between 0 & 32767
  RESTING=$((RANDOM/60))
  sleep ${RESTING}
fi

# We now download the MSRBL files using the the specified program.
case ${GET_MSRBL} in
  1)
  cd ${MSR_DIR}
  rsync ${RSYNC_OPTS} --files-from="${MSR_DIR}/msrbl-files.txt" ${MSRBL} ${MSR_DIR}
    for M in $(ls *.?db *.db 2>/dev/null); do
      chmod 0664 ${M}
      chown ${C_USER}:${C_GROUP} ${M}
      cp -pf ${M} ${T_DIR}
    done
  ;;
esac

## Delete unused securiteinfo files
unset OLD_SECURITE_FILES
case ${GET_SECURITE} in
  0)
  OLD_SECURITE_FILES=${SECURITE_A[@]}
  ;;
  1)
  OLD_SECURITE_FILES="
securiteinfobat.hdb
securiteinfodos.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb"
  ;;
  2)
  OLD_SECURITE_FILES="
securiteinfoelf.hdb
securiteinfo.hdb
securiteinfohtml.hdb
securiteinfooffice.hdb
securiteinfopdf.hdb"
  ;;
  3)
  OLD_SECURITE_FILES="
securiteinfobat.hdb
securiteinfodos.hdb
securiteinfoelf.hdb
securiteinfooffice.hdb
securiteinfosh.hdb"
  ;;
esac

# Delete any obsolete securiteinfo files in the clamav database
cd ${CLAMAV_DB}
for D in ${OLD_SECURITE_FILES}; do
  if [[ -e ${D} ]]; then
    rm -f ${D}
  fi
done

# Now delete them in the securite directory also
cd ${SI_DIR}
for D in ${OLD_SECURITE_FILES}; do
  if [[ -e ${D} ]]; then
    rm -f ${D}
  fi
done

# See if the ${GET_SECURITE} flag is set
if [[ ${GET_SECURITE} -gt 0 ]]; then
# If set, change to the securiteinfo directory
  cd ${SI_DIR}
  case ${GET_SECURITE} in
  1)
# Linux specific files
  si_files="
http://clamav.securiteinfo.com/honeynet.hdb
http://clamav.securiteinfo.com/securiteinfo.hdb
http://clamav.securiteinfo.com/securiteinfoelf.hdb
http://clamav.securiteinfo.com/securiteinfosh.hdb"
  ;;
  2)
# Windows specific files
  si_files="
http://clamav.securiteinfo.com/honeynet.hdb
http://clamav.securiteinfo.com/securiteinfo.hdb
http://clamav.securiteinfo.com/securiteinfobat.hdb
http://clamav.securiteinfo.com/securiteinfodos.hdb
http://clamav.securiteinfo.com/securiteinfohtml.hdb
http://clamav.securiteinfo.com/securiteinfooffice.hdb
http://clamav.securiteinfo.com/securiteinfopdf.hdb"
  ;;
  3)
# Web specific files
  si_files="
http://clamav.securiteinfo.com/honeynet.hdb
http://clamav.securiteinfo.com/securiteinfo.hdb
http://clamav.securiteinfo.com/securiteinfohtml.hdb
http://clamav.securiteinfo.com/securiteinfopdf.hdb"
;;
 4)
# All securite files
  si_files="
http://clamav.securiteinfo.com/honeynet.hdb
http://clamav.securiteinfo.com/securiteinfo.hdb
http://clamav.securiteinfo.com/securiteinfobat.hdb
http://clamav.securiteinfo.com/securiteinfodos.hdb
http://clamav.securiteinfo.com/securiteinfoelf.hdb
http://clamav.securiteinfo.com/securiteinfohtml.hdb
http://clamav.securiteinfo.com/securiteinfooffice.hdb
http://clamav.securiteinfo.com/securiteinfopdf.hdb
http://clamav.securiteinfo.com/securiteinfosh.hdb"
  ;;
  esac

  for D in ${si_files}
    do
      FN=$(basename ${D})
        if [[ "${DL_AGENT}" == "curl" ]]; then
          curl ${CMD} -z "${FN}" ${D}
        elif [[ "${DL_AGENT}" == "wget" ]]; then
          wget ${CMD} ${D}
        else
          printf "\n\tWe don't seem to have a download agent to download the"
          printf "\n\tSecuriteinfo files. Sorry, but we have to exit\n"
# Error, no download agent -- exit with error code 6
          exit 6
        fi
    done

# Clear the SI variable if set
unset SI
# Fix file permissions
  for SI in $(ls *.?db *.db 2>/dev/null); do
    chmod 0664 ${SI}
    chown ${C_USER}:${C_GROUP} ${SI}
#    mv -f ${SI} ${T_DIR}
     cp -fp ${SI} ${T_DIR}
  done
fi

case ${GET_MALWARE} in
 1)
# Get the Malware files
  cd ${MW_DIR}
  for D in ${MW_URL}
    do
      FN=${MW_FILE}
        if [[ "${DL_AGENT}" == "curl" ]]; then
          curl -q -L -s -S --output "${MW_DIR}/${MW_FILE}" -z "${MW_DIR}/${MW_FILE}" ${D}
        elif [[ "${DL_AGENT}" == "wget" ]]; then
          wget -q -O "${MW_DIR}/${MW_FILE}" ${MW_URL}
        else
          printf "\n\tWe don't seem to have a download agent to download the"
          printf "\n\tMalware files. Sorry, but we have to exit\n"
# Error, no download agent -- exit with error code 6
          exit 6
        fi
    done

# Change file permission & ownership and copy to TMP directory.
  for MW in $(ls *.ndb 2>/dev/null); do
    chmod 0664 ${MW}
    chown ${C_USER}:${C_GROUP} ${MW}
    cp -fp ${MW} ${T_DIR}
  done
  ;;
esac

# Winnow files
if [[ ${GET_WINNOW} -eq 1 ]]; then
  case ${WPC} in
    1)
      w_files=${W_FILES_1A[@]}
    ;;
    2)
      w_files=${W_FILES_2A[@]}
    ;;
    3)
      w_files=${W_FILES_3A[@]}
    ;;
  esac
fi

# See if an old version of the "sane_include.txt" file exists. Remove it it
# it does.
cd ${SANE_DB}
if [[ ${SANE_DB}/sane_include.txt ]]; then
  rm -f ${SANE_DB}/sane_include.txt
# Create an empty "sane_include.txt" file
  touch ${SANE_DB}/sane_include.txt
# Adjust the file ownership and permissions
  chown ${C_USER}:${C_GROUP} ${SANE_DB}/sane_include.txt
  chmod 0664 ${SANE_DB}/sane_include.txt
fi
# if downloading sane files not disabled
if [[ ${GET_SANE} -eq 1 ]]; then
  printf "%s\n" ${SANE_A[@]} >> ${SANE_DB}/sane_include.txt
fi
# if winnow files not disabled
if [[ ${GET_WINNOW} -gt 0 && ${GET_SANE} -eq 1 ]]; then
  printf "%s\n" ${w_files} >> ${SANE_DB}/sane_include.txt
fi
# if ldb file not disabled
if [[ ${GET_LDB} -eq 1 && ${GET_SANE} -eq 1 ]]; then
  printf "%s\n" ${LDB_A[@]} >> ${SANE_DB}/sane_include.txt
fi

# Assign ${INCLUDE_FILES} = ${SANE_DB}/sane_include.txt
INCLUDE_FILES="--files-from=${SANE_DB}/sane_include.txt"

# Download the sanesecurity files via rsync
rsync ${RSYNC_OPTS} ${INCLUDE_FILES} ${SANE} ${SANE_DB}
# Change the file ownership and mode
for C in $(ls *.sig *.?db *.ftm *.ign2 2>/dev/null); do
  chmod 0664 ${C}
  chown ${C_USER}:${C_GROUP} ${C}
done

if [[ ${GET_SANE} -gt 0 ]]; then
  # Check the signature - discard if bad
  for F in $(ls *.?db *.ftm *.ign2 2>/dev/null)
    do
      if ! gpg_out=$(${GPG_AGENT} ${GPG_OPT} --verify "${F}.sig" "${F}" 2>&1); then
        echo "Security Error ${F} is missing gpg sig" >&2
        echo "${gpg_out}" >&2
        rm -f "${F}.sig" "${F}"
      else
        cp -fp ${F} ${T_DIR}
      fi
    done
      if [[ ${SANE_DB}/sane_include.txt ]]; then
        rm -f ${SANE_DB}/sane_include.txt
      fi
fi
}
## ============================== function log ============================== ##
# The "log" function creates log file It is configurable when the script
# is installed using the ${MK_LOG} variable or via the command
# line: [L|l] flags.

function log ()
{
if [[ ${MK_LOG} -gt 0 ]]; then
  local LOG_FILE_DATE=$(date "+%y-%m")
  local LOG_FILE_SUFFIX=".log"
  local LOG_NAME="scamp"
  local LOG_PATH="/var/log/"
  local D_FORMAT=$(date "+%B %d %T scamp:")
    if [[ ${L_TYPE} -eq 1 ]]; then
      local LOG_FILE="${LOG_PATH}${LOG_NAME}-${LOG_FILE_DATE}${LOG_FILE_SUFFIX}"
    else
      local LOG_FILE="${LOG_PATH}${LOG_NAME}${LOG_FILE_SUFFIX}"
    fi

    if [[ ! -s ${LOG_FILE} ]]; then
      touch ${LOG_FILE}
      chown ${C_USER}:${C_GROUP} ${LOG_FILE}
      chmod 0644 ${LOG_FILE}
    fi
    printf "${D_FORMAT} Updated %d.  Not Updated %d.  Failed %d.\n" ${INSTALLED} ${NO_UPDATE} ${FAILED} >> ${LOG_FILE}
fi
}
## ========================== function log_syslog =========================== ##
# The log_syslog function turns on logging to the system log. Is is configurable
# via the ${SYS_LOG} variable. It can also be turned on/off via the command
# line flags: [L|l]

# Syslog function

function log_syslog ()
{
local LOG_FILE="${T_DIR}/$(date "+%s")"
local D_FORMAT=$(date "+%B %d %T")
local TAG="-t scamp"
printf "Updated %d.  Not Updated %d.  Failed %d.\n" ${INSTALLED} ${NO_UPDATE} ${FAILED} > ${LOG_FILE}
logger -i ${TAG} -f "${LOG_FILE}"
rm -f ${LOG_FILE}
}
## ========================== function make_config ========================== ##
# The "make_config" function is where we create the configuration files for
# the script. It is passed the name of the configuration file to create.

function make_config ()
{
clear
  if [[ ${1} ]]; then
    CONFIG_FILE=${1}
  fi

while [[ ! ${clamav_db} ]]; do
  printf "\f"
    if [[ -n ${ER_1} ]]; then
      printf "${ER_1}\n\n"
    fi
  printf "Enter the location of the Clamav Database. It must be a Fully Qualified
path. Check your documentation. If it is entered incorrectly, the script will
fail. Usually locations:\n
/var/db/clamav
/var/lib/clamav
/usr/local/share/clamav\n
You MUST enter a PATH if not defined!\n
Press <RETURN> to accept the default (if defined) -- or modify if required
Clamav Database location:\n\n"
  if [[ -z ${CLAMAV_DB} ]]; then
    printf "[NO DEFAULT SETTING] "
    read clamav_db
    assign_value ${clamav_db} CLAMAV_DB
  else
    printf "[Default: %s ] " ${CLAMAV_DB}
    read clamav_db
    assign_value ${clamav_db} CLAMAV_DB
    break
  fi
done

clear
printf "\n
===============================================================================
\n"

# Get the rest of the needed config file variables.
printf "All settings may be set to DEFAULT by pressing <RETURN> at each option.\n"

# Set the tmp directory if it doesn't exist
if [[ -z ${T_DIR} ]]; then
  T_DIR="${CLAMAV_DB}/tmp"
fi
printf "\n\nYou may set the temp directory to be used by this script here.\n\n"
printf "Enter the Fully Qualified PATH here.\n
[Default = %s ] " ${T_DIR}
read t_dir
assign_value ${t_dir} T_DIR

clear
printf "\n
===============================================================================
\n"

printf "Check the 'PidFile' setting in your clamd.conf file
for the location of the Clamd PID file\n\n
Enter the fully qualified file name of the PID file:\n
[Default: %s ] " ${C_PID}
read c_pid
assign_value ${c_pid} C_PID

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Do you want to turn on the random download timer?
It only works when run via CRON. 1=on & 0=off\n
[default: %d ] " ${REST}
  read rest
  null_char ${rest}
  valid_num ${rest} 0 1
done
assign_value ${rest} REST

clear
printf "\n
===============================================================================
\n"

printf "Enter: GROUP ownership of files:\n
[default: %s ] " ${C_GROUP}
read c_group
assign_value ${c_group} C_GROUP

clear
printf "\n
===============================================================================
\n"

printf "Enter: USER ownership of files:\n
[default: %s ] " ${C_USER}
read c_user
assign_value ${c_user} C_USER

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Install the Sanesecurity files: 1=yes & 0=no\n
[default = %d ] " ${GET_SANE}
  read get_sane
  null_char ${get_sane}
  valid_num ${get_sane} 0 1
done
assign_value ${get_sane} GET_SANE

clear
printf "\n
===============================================================================
\n"

if [[ ${GET_SANE} -eq 1 ]]; then
IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "The Sanesecurity *.ldb files only work with Clamav >=0.94
DO NOT download if you have an older version of Clamav installed.
See http://vrt-sourcefire.blogspot.com/2008/09/logical-signatures-in-clamav-094.html for further details.\n\n"
  printf "\nInstall the Sanesecurity *.ldb files: 1=yes & 0=no\n
[Default = %d ] " ${GET_LDB}
  read get_ldb
  null_char ${get_ldb}
  valid_num ${get_ldb} 0 1
done
assign_value ${get_ldb} GET_LDB
else
  GET_LDB=0
  WPC=0
  GET_WINNOW=0
fi

clear
printf "\n
===============================================================================
\n"

if [[ ${GET_SANE} -eq 1 ]]; then
  IS_DIGIT=0
    while [[ ${IS_DIGIT} -eq 0 ]]; do
      printf "Install the Winnow files?\n
Please see: http://winnow.oitc.com/clamsigs/index.html for full details.\n\n"
      printf "1=yes & 0=no\n
[Default = %d ] " ${GET_WINNOW}
      read get_winnow
      null_char ${get_winnow}
      valid_num ${get_winnow} 0 1
    done
assign_value ${get_winnow} GET_WINNOW

clear

  if [[ ${GET_WINNOW} -eq 1 ]]; then
    ans=0
      while [[ ${ans} -eq 0 ]]; do
        IS_DIGIT=0
        while [[ ${IS_DIGIT} -eq 0 ]]; do
printf "winnow files provided are:

(1) Non-Scoring Files:

${bldylw}winnow.attachments.hdb${txtrst} - Signatures to detect images and other attachments
in active spam runs(False positive rate is low)

${bldylw}winnow.complex.patterns.ldb${txtrst} - Hand created signatures to detect fraud and
other malicious spam.(Very low false positive rate)

${bldylw}winnow_extended_malware_links.ndb${txtrst} - Signatures to detect active url's associated
with malware in winnow_extended_malware.hdb. This contains both older signatures not
incorporated in official clamav databases or are large files not transported typically
via email(Might be used in mail systems. Very low false alarm rate)

${bldylw}winnow_malware.hdb${txtrst} - Current virus, trojan and other malware not yet detected by ClamAV.

${bldylw}winnow_malware_links.ndb${txtrst} - Signatures to detect links to malware in winnow_malware.hdb
and links to other malicious malware. (Scoring is not required on these signatures)

${bldylw}winnow_phish_complete_url.ndb${txtrst} - Similar to winnow_phish_complete.ndb except that entire
urls's are used to derive the signatures rather than carefully selected hosts.
(Conservative) Be advised that by using these complete url signatures, fast flux
phishing sites as well as phishing sites that use obfuscated urls and those that
insert trash in urls to confuse anti-malware systems may not be reliably
detected by some of these signatures.
(Conservative and can be used without scoring)

(2) Scoring Files:

${bldylw}winnow_spam_complete.ndb${txtrst} - Signatures to detect fraud and other malicious spam.
This collection of signatures are derived using special processing on data sent to spam traps and
honeypots.(Scoring of these signatures is recommended)

${bldylw}winnow_phish_complete.ndb${txtrst} - Signatures to detect phishing and other malicious url's
and compromised hosts. This collection of signatures are derived by checking many
data feeds (see below) coupled with special processing to remove the possibility
of false positives. (Recommended to be used with scoring)

(3) All Files - Above sans winnow_phish_complete_url.ndb:

(1) = Install the non-scoring files only
(2) = Install the scoring recommended files only
(3) = Install all winnow files

[Default = %d ] " ${WPC}
  read wpc
  null_char ${wpc}
  valid_num ${wpc} 1 3
  done
  assign_value ${wpc} WPC
  ans=1
      done
  fi
fi

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "The MSRBL files are no longer being updated.
Their use is not recommended."
  printf "\nInstall the MSRBL files: 1=yes & 0=no\n
[default = %d ] " ${GET_MSRBL}
  read get_msrbl
  null_char ${get_msrbl}
  valid_num ${get_msrbl} 0 1
done
assign_value ${get_msrbl} GET_MSRBL

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Install the Malware files: 1=yes & 0=no\n
[default = %d ] " ${GET_MALWARE}
  read get_malware
  null_char ${get_malware}
  valid_num ${get_malware} 0 1
done
assign_value ${get_malware} GET_MALWARE

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
printf "There are three (3) general classifications for the SecuriteInfo files:

\t1) Linux
\t2) Windows
\t3) HTML (web servers)

By default, all three classifications are installed. You may choose to limit
this to only a specific catagory, or not install any of them.

Please enter: 0 to not install the files
              1 to install the Linux specific files
              2 to install the Windows specific files
              3 to install the Web Server specific files
              4 to install all of the SecurityInfo files (default)\n\n"
  printf "Install the Securiteinfo files: [0,1,2,3,4]\n
[default = %d ] " ${GET_SECURITE}
  read get_securite
  null_char ${get_securite}
  valid_num ${get_securite} 0 4
done
assign_value ${get_securite} GET_SECURITE

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Reload clamd after update: 1=yes & 0=no\n
[default = %d ] " ${RELOAD}
  read reload
  null_char ${reload}
  valid_num ${reload} 0 1
done
assign_value ${reload} RELOAD

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Do you want a summary screen printed out when finished?
Enter 1 to display the screen or 0 to skip it.\n
Usually set to 0 when running via CRON.\n
[Default = %d ] " ${W_SUM}
  read w_sum
  null_char ${w_sum}
  valid_num ${w_sum} 0 1
done
assign_value ${w_sum} W_SUM

clear
printf "\n
===============================================================================
\n"

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Do you want to create a log file?
Default Location: /var/log/scamp.log\n
Enter 1 for yes & 0 for no.\n
[Default = %d ] " ${MK_LOG}
  read mk_log
  null_char ${mk_log}
  valid_num ${mk_log} 0 1
done
assign_value ${mk_log} MK_LOG

clear
printf "\n
===============================================================================
\n"

if [[ ${MK_LOG} -eq 1 ]]; then
IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "The basic log file is named scamp.log in the /var/log directory.\n"
  printf "Do you want to use that name or one that is incremented each month?\n\n"
  printf "EXAMPLE: scamp-09-03.log (log for March 2009)\n\n"
  printf "Enter 0 for 'scamp.log' & 1 for 'scamp<date>.log'\n
[Default = %d ] " ${L_TYPE}
  read l_type
  null_char ${l_type}
  valid_num ${l_type} 0 1
done
assign_value ${l_type} L_TYPE

clear
printf "\n
===============================================================================
\n"

fi

IS_DIGIT=0
while [[ ${IS_DIGIT} -eq 0 ]]; do
  printf "Scamp can also log to the system logger.\n"
  printf "Would you like to enable this feature?\n\n"
  printf "\n0 = off & 1 = on\n
[Default = %d ] " ${SYS_LOG}
  read sys_log
  null_char ${sys_log}
  valid_num ${sys_log} 0 1
done
assign_value ${sys_log} SYS_LOG

clear
printf "\n
===============================================================================
\n"

  printf "Do you want to set the GNUPGHOME environment variable?\n"
  printf "Read man gpg2 for further information\n\n"
  printf "If in doubt, leave blank; i.e., just hit <RETURN>\n"
  printf "Enter PATH or <RETURN> to unset it.\n
[Default = %s ] " ${GNUPGHOME}
read gnupghome_var
  if [[ -n $gnupghome_var ]]; then
    assign_value ${gnupghome_var} GNUPGHOME_VAR
  fi

clear
printf "\n
===============================================================================
\n"

# Print out a completion message
printf "
\tPlease Wait\n
\tWe are now configuring the system and installing the files\n"

: << Write-Config
This is where we actually write the configuration file. It should only be done
once or when there is a change in the configuration file.
Write-Config

if [[ ${EDIT_CONFIG} -eq 0 ]]; then
  touch ${CONFIG_FILE}
  printf "# This is the ${CONFIG_FILE} file.\n" >> ${CONFIG_FILE}
  printf "# Created %s %s %s %s %s\n\n" $(date "+%B %d, %Y @ %T") >> ${CONFIG_FILE}
elif [[ ${EDIT_CONFIG} -eq 1 ]]; then
  printf "\n\tInstall the new ${CONFIG_FILE} - Y or y to install: "
  unset ans
  read ans
  if [ "${ans}" == "y" -o "${ans}" == "Y" ]; then
    rm -f ${CONFIG_FILE}
  else
    printf "\n\tRetaining old ${CONFIG_FILE}\n"
    printf "\n\tExiting Program\n"
    exit 0
  fi
fi

# Place the version number in config file
echo SCAMP_VERSION=${VERSION} >> ${CONFIG_FILE}

# Location of the main Clamav data base
echo CLAMAV_DB=${CLAMAV_DB} >> ${CONFIG_FILE}

# Sets the tmp directory
echo T_DIR=${T_DIR} >> ${CONFIG_FILE}

# Set the Clamav group owner
echo C_GROUP=${C_GROUP} >> ${CONFIG_FILE}

# Set the location for the 'clamd.pid' file
echo C_PID=${C_PID} >> ${CONFIG_FILE}

# Set the user
echo C_USER=${C_USER} >> ${CONFIG_FILE}

# Whether to download the *.ldb files - 1 means yes and 0 means no
echo GET_LDB=${GET_LDB} >> ${CONFIG_FILE}

# Get Malware files - 1 means yes
echo GET_MALWARE=${GET_MALWARE} >> ${CONFIG_FILE}

# Get the MSRBL files - 1 means yes
echo GET_MSRBL=${GET_MSRBL} >> ${CONFIG_FILE}

# Get the sanesecurity files - 1 means yes
echo GET_SANE=${GET_SANE} >> ${CONFIG_FILE}

# Get the securiteinfo files - 1 means yes
echo GET_SECURITE=${GET_SECURITE} >> ${CONFIG_FILE}

# Get winnow files
echo GET_WINNOW=${GET_WINNOW} >> ${CONFIG_FILE}

# Save the GNUPGHOME environment variable if entered
  if [[ -n ${GNUPGHOME_VAR} ]]; then
    echo GNUPGHOME_VAR=${GNUPGHOME_VAR} >> ${CONFIG_FILE}
  fi

# Location of the sanesecurity key
echo gpg_key_url="http://www.sanesecurity.net/publickey.gpg" >> ${CONFIG_FILE}

# Save the log file type
echo L_TYPE=${L_TYPE} >> ${CONFIG_FILE}

# Whether to create a log file
echo MK_LOG=${MK_LOG} >> ${CONFIG_FILE}

# MSRBL URL
echo MSRBL="rsync://rsync.mirror.msrbl.com/msrbl/" >> ${CONFIG_FILE}

# These are the individual MSRBL files
echo msrbl_Images='MSRBL-Images.hdb' >> ${CONFIG_FILE}
echo msrbl_SPAM='MSRBL-SPAM.ndb' >> ${CONFIG_FILE}
echo msrbl_SPAM_CR='MSRBL-SPAM-CR.ndb' >> ${CONFIG_FILE}

# Sets the msrbl directory
echo MSR_DIR="${T_DIR}/msr" >> ${CONFIG_FILE}

# Set the Malware dir
echo MW_DIR="${T_DIR}/malware" >> ${CONFIG_FILE}

# Malware file name
echo MW_FILE="mbl.ndb" >> ${CONFIG_FILE}

# Malware URL
echo MW_URL="http://www.malwarepatrol.com.br/cgi/submit?action=list_clamav_ext" >> ${CONFIG_FILE}

# Whether to reload clamd if new files are installed - NO to stop
echo RELOAD=${RELOAD} >> ${CONFIG_FILE}

# Set the random download function - 0=off & 1=on
echo REST=${REST} >> ${CONFIG_FILE}

# Sanesecurity URL
echo SANE="rsync://rsync.sanesecurity.net/sanesecurity" >> ${CONFIG_FILE}

# Sanesecurity tmp directory
echo SANE_DB="${T_DIR}/sane" >> ${CONFIG_FILE}

# Set the Securiteinfo dir
echo SI_DIR="${T_DIR}/securite" >> ${CONFIG_FILE}

# Save the sys-log setting
echo SYS_LOG=${SYS_LOG} >> ${CONFIG_FILE}

# Which winnow file
echo WPC=${WPC} >> ${CONFIG_FILE}

# Whether to display the summary screen
echo W_SUM=${W_SUM} >> ${CONFIG_FILE}

chmod 0664 ${CONFIG_FILE}

# We now exit since a new config file has been installed
printf "\n\tCongratulations, you may now run the program normally\n\n"
exit
}
## =========================== function null_char =========================== ##
# Check to see if any data was entered. If not, then breaks out of the loop,
# else it returns the character entered. This function calls the
# "test_char function". I kept them separate so that I might more easily modify
# them if it became necessary.

function null_char ()
{
num=${1}
if [[ -z ${num} ]]; then
  break
else
  test_char ${num}
fi
}
## =========================== function readconf ============================ ##
# This function reads the scamp configuration file.
function readconf () {
while read line; do
# skip comments
  [[ ${line:0:1} == "#" ]] && continue
# skip empty lines
  [[ -z "${line}" ]] && continue
  eval ${line}
done < "${CONFIG_FILE}"
}
## ========================== function reload_db =========================== ##
# This is the reload function. It reloads "clamd" if "${INSTALLED}" is not zero.

function reload_db ()
{
# See if any files were installed
if [[ ${INSTALLED} -gt 0 ]]; then
# See if we are to reload clamd after update
  if [[ "${RELOAD}" -gt 0 ]]; then
  # Check to see if the path to the PID file is set
    if [[ ${C_PID} ]]; then
  # Now make sure that the file actually exists
      if [[ -s ${C_PID} ]]; then
        CLAMD_PID=$(cat ${C_PID})
      fi
  # OK, the file doesn't exist so try to get the PID of the clamd program
    elif command -v pidof 2>/dev/null; then
      CLAMD_PID=$(pidof clamd)
    else
    # Maybe 'pidof' is not available. Try a more direct method
      if [[ $(ps -U ${C_USER} | awk '/clamd/ { print $1 }') ]]; then
        CLAMD_PID=$(ps -U ${C_USER} | awk '/clamd/ { print $1 }')
      else
      # OK, we cannot get the PID. Set $RELOAD to NO
        if [[ ! ${CLAMD_PID} ]]; then
          printf "${txtylw}Unable to get clamd PID. Turning 'RELOAD' off${txtrst}\n"
          RELOAD=0
        fi
      fi
    fi
  fi
  if [[ "${RELOAD}" -gt 0 ]]; then
# Check if clamd is running
    if [[ -z "${CLAMD_PID}" ]]; then
# CLAM_PID not set
      printf "${txtylw}\tCLAM_PID not set. Unable to restart clamd.${txtrst}\n"
    else
      kill -USR2 ${CLAMD_PID}
        if [[ ${W_SUM} -gt 0 ]]; then
          printf "\t${txtgrn}Database Reloaded${txtrst}\n"
        fi
    fi
  fi
fi
}
## ========================== function strip_path =========================== ##
# $1 is the full path & file name passed to this function
# It returns the file name sans path in the ${fname} variable
# It first unsets any old ${fname} variables
function strip_path ()
{
unset fname
fname=${1##*/}
}
## ============================ function summary ============================ ##
# The "summary" function print out a screen which details what the script has
# just done. This function can be activated/or deactivated via the ${W_SUM}
# flag when the script is configured or using the command line: [Q|q] flags.

function summary ()
{
# See if we are to print out a summary
if [[ ${W_SUM} -gt 0 ]]; then
# If a file has been installed, start here.
  if [[ ${INSTALLED} -gt 0 ]]; then
    printf "\n\tFiles saved to: %s\n\n" ${CLAMAV_DB}
    printf "\tInstalled:   %d\n" ${INSTALLED}
    printf "\tNot Updated: %d\n" ${NO_UPDATE}
    printf "\tFailed:      %d\n\n" ${FAILED}
  else
# If a new file has not been installed, we branch here.
    INSTALLED=0
    printf "\n\tReloading of the database not required.\n\n"
    printf "\tInstalled:   %d\n" ${INSTALLED}
    printf "\tNot Updated: %d\n" ${NO_UPDATE}
    printf "\tFailed:      %d\n\n" ${FAILED}
  fi
fi
}
## ========================== function test_char =========================== ##
# A simple function to check if the input is a digit. It is called by the
# "null_char function" if data was entered.

function test_char ()
{
IS_DIGIT=0

# Returned data from "function null_char"
case "$1" in
  [[:digit:]] )
    IS_DIGIT=1
  ;;
  * )
printf "\n\a\t   *****WARNING*****
\tYou must enter a digit\n\n"
  ;;
esac
}
## ============================= function unzip ============================= ##
# This is the unzip function. It does exactly what its name implies.
# This function is nolonger being used; however, I thought it best to leave it
# here in case I need to use it again in the future. It is passed the directory
# name to change to and unzips any files it finds. First it modifies the file's
# permissions.

function unzip ()
{
# Change to the correct directory
cd ${1}
# Change file permission's and ownership
for ZF in $(ls *.gz 2>/dev/null); do
  chown ${C_USER}:${C_GROUP} ${ZF}
  chmod 0664 ${ZF}
done

# Get a listing of the *.gz files
ZIPFILES=( $(ls *.gz 2>/dev/null) )

# Set variables
LIMIT=0
ZIPFILES_COUNT=${#ZIPFILES[*]}

while [ ${LIMIT} -lt ${ZIPFILES_COUNT} ]; do
# Get the files name and strip the '.gz' extension
  NoGZ=${ZIPFILES[$LIMIT]/%.gz/}
# Save the original gunzip file and its unzipped version
  gunzip -qfN <${ZIPFILES[$LIMIT]}> ${NoGZ}
# Capture the exit code
  GZEC=$?
    case ${GZEC} in
      [0]*)
# No problems.
      :
      ;;
      [1]*)
# Gunzip has a problem.
# Check the error code and try again!
      printf "\tgunzip issued error code %d\n" ${GZEC}
      printf "\tUnable to gunzip %s\n" ${ZIPFILES[$LIMIT]}
      printf "\tPlease try again later\n"
      ;;
      [2]*)
# Gunzip issued a warning. We will attempt to continue.
      printf "\tgunzip issued warning code %d\n" ${GZEC}
      printf "\tWe will attempt to continue\n"
      ;;
    esac
  LIMIT=$((LIMIT+1))
done
}
##  ===========================function valid_num =========================== ##
# This function simply checks to see if the value entered was legal. It is pass
# the number 'input' and its lower and upper limits. It returns either "0" if
# the test failed or "1" if it passed.

function valid_num ()
{
  if [[ ${1} -lt ${2} || ${1} -gt ${3} ]]; then
    printf "\nYou must enter a number between %d and %d\n" ${2} ${3}
    printf "\nEnter any key to continue!"
    read x
    clear
    IS_DIGIT=0
  else
    IS_DIGIT=1
  fi
}


## ============================= END FUNCTIONS ============================== ##
#
## ======================= START OF PROGRAM EXECUTION ======================= ##
# Check for a configuration file and reread if if present.
# See if the config directory exists
if [[ -z ${CONFIG_DIR} ]]; then
  make_config
elif ! [[ -d ${CONFIG_DIR} ]]; then
  mkdir -p -m 0755 ${CONFIG_DIR}
fi

if [[ -s ${CONFIG_FILE} ]]; then
  readconf
else
  if [[ ! -t 0 ]]; then
# If running via CRON, print error message and exit.
    printf "\tYou need to create a configuration file before you\n"
    printf "\tyou can run this script.\n\n"
    printf "\tWe have to exit. Try again from the console\n"
    exit
  fi
# If not running via CRON and no configuration file exists, create one.
# Call the "make_config" function and pass it the config file name.
  make_config ${CONFIG_FILE}
fi

## Make sure the database location is set properly
if [[ -z ${CLAMAV_DB} ]]; then
  make_config
fi

## Make sure the directory exist. Create if not.

for D in ${T_DIR} ${SANE_DB} ${MSR_DIR} ${SI_DIR} ${MW_DIR}
  do
    if [[ ! -d ${D} ]]; then
      mkdir -p -m 0755 ${D}
      chown ${C_USER}:${C_GROUP} ${D}
      MEC=$?
        case ${MEC} in
          [0]*)
# No problems
            :
          ;;
          *)
# Something happened - the directory structure could not be created.
# The program is being forced to exit.
# This might be a file permission problem.
            printf "Unable to create %s
Check your system and rerun script\n
Exiting ...\n" ${D}
            exit 3
          ;;
        esac
    fi
  done

## Make sure the programs we need are present

if command -v curl &>/dev/null; then
  DL_AGENT="curl"
  CMD=" -q -s -S --remote-name --location --remote-time"
elif command -v wget &>/dev/null; then
  DL_AGENT="wget"
  CMD=" -q -N "
else
  echo "Neither curl or wget can be found. Exiting program"
fi

# We will exit if one of the four named programs are not found.
for f in clamscan gunzip cmp rsync
do
  if ! command -v ${f} &>/dev/null; then
    printf "
\tCannot find: %s\n
\tWe have to exit\n" ${f}
    exit 6
  fi
done

# We assume 'rsync' has been found
RSY="rsync"
# Set the basic options for rsync
# The "--quiet" switch suggested by Rene Berber for
# compatibility on Solaris systems. Apparently it prevents a superfluous
# email being sent when run via CRON
RSYNC_OPTS="--checksum --recursive --quiet --times --compress"

# Now check to make sure a version of 'gpg' is available
if [[ ${GET_SANE} -gt 0 ]]; then
  if command -v gpg2 &>/dev/null; then
    GPG_AGENT=$(command -v gpg2)
  elif command -v gpg &>/dev/null; then
    GPG_AGENT=$(command -v gpg)
  else
    printf "\n\tNeither gpg nor gpg2 not found
\tDisabling the downloading of Sanesecurity files.\n\n"
    GET_SANE=0
  fi
fi

# Set the GNUPGHOME  variable if it is available
# We have to wait until the config file is read before setting this.
if [[ -n ${GNUPGHOME_VAR} ]]; then
  export GNUPGHOME=${GNUPGHOME_VAR}
fi
#
# GPG options
# check to see it the ~/.gnupg directory exists
if [[ -d ~/.gnupg ]]; then
  GPG_OPT="--no-options -q --no-default-keyring --keyring ${SANE_DB}/pubring.gpg"
else
  GPG_OPT="-q --no-default-keyring --keyring ${SANE_DB}/pubring.gpg"
fi

# Set up GPG, if necessary
if [[ ${GET_SANE} -gt 0 ]]; then
  cd ${SANE_DB}
  if [ ! -s "${SANE_DB}/pubring.gpg" ]; then
    printf "\n\n
\tNo GPG keyring found; initialising
\t(This should only occur once)\n\n
\tPlease Stand By ***\n"
      case ${DL_AGENT} in
      [wget]*)
        if ! wget -O - "${gpg_key_url}" | ${GPG_AGENT} ${GPG_OPT} --import -
          then
           printf "\tERROR: could not import GPG public key; aborting\n"
          exit 7
        fi
      ;;
      [curl]*)
        if ! curl -q -s -S "${gpg_key_url}" | ${GPG_AGENT} ${GPG_OPT} --import -
          then
            printf "\tERROR: could not import GPG public key; aborting\n"
          exit 7
        fi
      ;;
      *)
        printf "\tNeither 'curl' nor 'wget' available. We are forced to exit\n"
        exit 6
      ;;
      esac
  fi
  chown ${C_USER}:${C_GROUP} "${SANE_DB}/pubring.gpg"
  chmod 0664 "${SANE_DB}/pubring.gpg"
# Remove the superfilous 'pubring.gpg~' file if it exists
  if [[ -e "${SANE_DB}/pubring.gpg~" ]]; then
    rm -f "${SANE_DB}/pubring.gpg~"
  fi
fi

## ============================== MENU OPTIONS ============================== ##
# Get any command line options
while getopts "cC:De:hlLqQrRv" Option
do
case $Option in
h)
  clear
  printf "
USAGE: $0 [ [-c|-C <name>] [-D ] [-e <name>] [-h|-v] [-l|-L] [-q|-Q] [-r|-R] ]\n
\t(-c) to create a new default config file
\t     delete old file & exit after completion\n
\t(-C <name>) to create a new config file or use an existing one.\n
\t(-D) Deletes all definitions and configuration files\n
\t(-h) to view this help message\n
\t(-e <name>) edit an existing config file\n
\t(-l) (lower case ell) to turn off logging\n
\t(-L) to activate logging\n
\t(-q) to skip printing the summary screen\n
\t(-Q) to display a summary screen\n
\t(-r) to deactivate the random download timing feature\n
\t(-R) to activate the random download feature\n
\t(-v) to view the script version and exit\n"

# Exit after displaying the help screen
  exit
;;
# Turn the logging function off.
l)
  MK_LOG=0
;;
#==============================================================================
# Basically nuke everything and start over
D)
clear

## See if we are running via CRON
if [[ ! -t 0 ]]; then
  printf "Sorry, you cannot use this option via CRON."
  exit
else
  printf "\nThis will delete all existing configuration and unofficial Clamav
definition files. Are you sure you want to proceed? Type "Y/y" to proceed.
Any other action will exit this program.\n\n"

  read answer
    if [[ ${answer} == "y" || ${answer} == "Y" ]]; then
    reload_db
    printf "\n\nWe will now delete all old definition and configuration files.\n"
    sleep 2
KILL_FILES="${SECURITE_A[@]} ${SANE_A[@]} ${WINNOW_A[@]} ${LDB_A[@]} ${MSRBL_A[@]} mbl.ndb"
    cd ${CLAMAV_DB}
    for k in ${KILL_FILES}; do
      if [[ -e ${k} ]]; then
        rm -f ${k}
      fi
    done

    if [[ -d ${T_DIR} ]]; then
      rm -Rdf ${T_DIR}
    fi

    if [[ -d ${CONFIG_DIR} ]]; then
      cd ${CONFIG_DIR}
        for i in $(ls * .* 2>/dev/null); do
          rm -f ${i}
        done
    clear
    fi
printf "\nReloading database\n"
printf "\nPlease run \"scamp.sh\" to create a new default config file. You will also
need to recreate any additionally configuration files using:\n
\tscamp.sh -C config_file_name\n\n"
    exit
  else
    exit
    fi
fi

;;
# Turn the logging function on.
L)
  MK_LOG=1
;;
# Turns on the random download timer. Works only via CRON
R)
  REST=1
  ;;
v)
  printf "\n\n\tVersion: %s\n\n" ${VERSION}
exit 0
;;
# Turn random timer off
r)
  REST=0
;;
# Turn summary output off
q)
  W_SUM=0
;;
# Turn summary output on
Q)
  W_SUM=1
;;
c)
if [[ ! -t 0 ]]; then
  printf "\tYou cannot use this function via CRON.\n"
  printf "\tWe have to exit. Try again from the console\n"
  exit
fi
printf "\f"
printf "\n\tAre you sure you want to erase your existing config file?\n"
printf "\n\tYou will be given the opportunity to create a new one.\n\n"
printf "\tAnswer [y|Y] to continue, anything else to exit. "
read answer
if [[ ${answer} == "y" || ${answer} == "Y" ]]; then
  if [[ -e ${CONFIG_FILE} ]]; then
    readconf
    rm ${CONFIG_FILE}
    make_config ${CONFIG_DIR}/default
  fi
else
  printf "\n\tEXITING PROGRAM\n"
  exit
fi
;;
C)
if [[ ${OPTARG:0:1} == "-" ]]; then
  printf "\n\tYou must enter a valid <name>\n\n"
  printf "\tEXAMPLE: ${0} -<option> <name>\n\n"
  printf "\tWe have to exit -- Sorry\n"
  exit
fi

CONFIG_FILE=${CONFIG_DIR}/${OPTARG}
if [[ -e ${CONFIG_FILE} ]]; then
  readconf
  break
fi
if [[ ! -e ${CONFIG_FILE} ]]; then
  if [[ ! -t 0 ]]; then
    printf "\tYou cannot use this function via CRON.\n"
    printf "\tWe have to exit. Try again from the console\n"
    exit
  fi
  printf "\f"
  printf "\n\tNo match found for %s\n" ${CONFIG_FILE}
  printf "\tWe will now procede to create the new config file.\n"
  printf "\n\tPress [X|x] to exit or any other key to continue: "
  read ANSWER
  if [[ ${ANSWER} = "x" || ${ANSWER} = "X" ]]; then
    printf "\n\tBye\n"
    exit
  else
    make_config ${CONFIG_FILE}
  fi
fi
;;
e)
if [[ ! -t 0 ]]; then
  printf "\tYou cannot use this function via CRON.\n"
  printf "\tWe have to exit. Try again from the console\n"
  exit
fi
#
if [[ ${OPTARG:0:1} == "-" ]]; then
  printf "\n\tYou must enter a valid <name>\n\n"
  printf "\tEXAMPLE: ${0} -<option> <name>\n\n"
  printf "\tWe have to exit -- Sorry\n"
  exit
fi
#
CONFIG_FILE="${CONFIG_DIR}/${OPTARG}"
if [[ ! -e ${CONFIG_FILE} ]]; then
  printf "\n\t%s does not exist\n" ${CONFIG_FILE}
  printf "\n\tEnter [y or Y] to create, or <RETURN> to exit. "
  unset ans
  read ans
  if [[ ${ans} == "y" || ${ans} == "Y" ]]; then
    printf "Creating the ${CONFIG_FILE}\n"
    EDIT_CONFIG=0
    make_config ${CONFIG_FILE}
  else
    printf "Exiting the program\n"
    exit
  fi
else
# Edit the config file.
  EDIT_CONFIG=1
  readconf
  make_config ${CONFIG_FILE}
fi
;;
#
*)
  printf "\nIncorrect flag - Enter $0 -h to view help menu.\n"
  exit 1
;;
esac
shift $(($OPTIND + 1))
done
## ================================ END MENU ================================ ##
## ==================== TRASH UNNEEDED DEFINITION FILES ===================== ##
# Remove unneeded files
for d in sane msrbl securite malware
  do
    case "${d}" in
      sane)
        if [ ${GET_SANE} -eq 0 -a -d ${SANE_DB} ]; then
            cd ${SANE_DB}
              for i in $(ls *.ndb *.hdb *.ftm *.ldb *.sig *.ign2 2>/dev/null); do
                rm -f ${i} 2>/dev/null
                  if [[ -d ${CLAMAV_DB} ]]; then
                    rm -f ${CLAMAV_DB}/${i} 2>/dev/null
                  fi
              done
          elif [ ${GET_SANE} -eq 0 -a -d ${CLAMAV_DB} ]; then
            cd ${CLAMAV_DB}
              for i in $(ls *.ndb *.hdb *.ftm *.ldb *.sig *.ign2 2>/dev/null); do
                rm -f ${i} 2>/dev/null
              done
        elif [ ${GET_LDB} -eq 0 -a -d ${SANE_DB} ]; then
          cd ${SANE_DB}
            for s in $(ls *.ldb *.ldb.sig 2>/dev/null); do
              rm -f ${s} 2>/dev/null
          if [[ -d ${CLAMAV_DB} ]]; then
            rm -f ${CLAMAV_DB}/${s} 2>/dev/null
          fi
            done
        fi
        if [[ ${GET_WINNOW} -eq 0 ]]; then
          if [[ -d ${SANE_DB} ]]; then
            cd ${SANE_DB}
              rm -f${WINNOW_A[@]}
                if [[ -d ${CLAMAV_DB} ]]; then
                  rm -f ${CLAMAV_DB}/${WINNOW_A[@]}
                fi
          fi
        elif [[ ${GET_WINNOW} -eq 1 && ${WPC} -eq 1 ]]; then
          if [[ -d ${SANE_DB} ]]; then
            cd ${SANE_DB}
              rm -f ${W_FILES_2A[@]}
                if [[ -d ${CLAMAV_DB} ]]; then
                  rm -f ${CLAMAV_DB}/${W_FILES_2A[@]}
                fi
          fi
        elif [[ ${GET_WINNOW} -eq 1 && ${WPC} -eq 2 ]]; then
          if [[ -d ${SANE_DB} ]]; then
            cd ${SANE_DB}
              rm -f ${W_FILES_1A[@]}
              if [[ -d ${CLAMAV_DB} ]]; then
                rm -f ${CLAMAV_DB}/${W_FILES_1A[@]}
              fi
          fi
        fi
    ;;
      msrbl)
        if [[ ${GET_MSRBL} -eq 0 ]]; then
          if [[ -d ${MSR_DIR} ]]; then
            cd ${MSR_DIR}
             for m in $(ls MSRBL* 2>/dev/null); do
              rm -f ${m}
                if [[ -d ${CLAMAV_DB} ]]; then
                  cd ${CLAMAV_DB}
                  rm -f ${m}
                fi
             done
          fi
        fi
    ;;
    securite)
      if [[ ${GET_SECURITE} -eq 0 ]]; then
        if [[ -d ${SI_DIR} ]]; then
         cd ${SI_DIR}
         rm -f ${SECURITE_A[@]}
           if [[ -d ${CLAMAV_DB} ]]; then
             cd ${CLAMAV_DB}
             rm -f ${SECURITE_A[@]}
           fi
        fi
      fi
    ;;
      malware)
        if [[ ${GET_MALWARE} -eq 0 ]]; then
          if [[ -d ${CLAMAV_DB} ]]; then
            cd ${CLAMAV_DB}
            for mw in $(ls mbl.ndb 2>/dev/null); do
             rm -f ${mw}
            done
          fi
          if [[ -d ${MW_DIR} ]]; then
            cd ${MW_DIR}
              for i in $(ls * 2>/dev/null); do
                rm -f ${i}
              done
          fi
        fi
    ;;
    esac
  done

## Call the functions
clean_up_tmp
get_files
check_install
summary
reload_db
log

if [[ ${SYS_LOG} -eq 1 ]]; then
  log_syslog
fi

## Clean up any garbage left behind
clean_up_tmp

## We are out of here!
exit 0

: << IMPORTANT
Good luck! Read the "README" file for the script documentation!

Any questions, suggestions, patches, etc. should be directed to me. I
really would appreciate it. To make tracking of 'bug' reports easier, please
do the following:

1) Go to: https://sourceforge.net/projects/scamp/
2) Click on "TRACKER"
3) Click on "Bug Reports"
4) Click on "Add New"
5) Fill out the report with complete information including the version of
   the script you are using, your OS and version of bash, rsync, gpg/gpg2,
   curl and/or wget and your version of Clamav. If possible, include the
   complete text of any error messages, etc.
IMPORTANT