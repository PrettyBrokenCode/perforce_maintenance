#!/bin/bash

TEMP=$(getopt -o n,w,t: -l gcloud_backup_role:,gcloud_user:,gcloud_setup,gcloud_bucket:,gcloud_project:,gcloud_backup_user:,nightly,weekly,ticket: -- "$@")
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

NIGHTLY=0
WEEKLY=0
TICKET=76A9F079C69FB1E444EF5A4F4A9049C6
GCLOUD_SETUP=0
GCLOUD_USER=-1
GCLOUD_BUCKET=-1
GCLOUD_PROJECT=-1
GCLOUD_BACKUP_ROLE=CloudBackupRole
GCLOUD_BACKUP_USER=-1
while true; do
    case "$1" in
        -n|--nightly) NIGHTLY=1; shift ;;
        -w|--weekly) WEEKLY=1; shift ;;
		--gcloud_setup) GCLOUD_SETUP=1; shift ;;
	-t|--ticket) 
		case $2 in
			"") echo "No ticket provided, using default ticket"; shift 2 ;;
			*) TICKET="$2"; shift 2 ;;
		esac ;;
	--gcloud_user)
		case $2 in
			"") echo "No gcloud user provided, exiting"; exit -1; shift 2 ;;
			*) GCLOUD_USER="$2"; shift 2 ;;
		esac ;;
	--gcloud_bucket)
		case $2 in
		"") echo "No gcloud bucket provided, exiting"; exit -1; shift 2 ;;
		*) GCLOUD_BUCKET="$2"; shift 2 ;;
		esac ;;
	--gcloud_project)
		case $2 in
		"") echo "No gcloud provided provided, exiting"; exit -1; shift 2 ;;
		*) GCLOUD_PROJECT="$2"; shift 2 ;;
		esac ;;
	--gcloud_backup_role)
		case $2 in
		"") echo "No gcloud backup role provided, exiting"; exit -1; shift 2 ;;
		*) GCLOUD_BACKUP_ROLE="$2"; shift 2 ;;
		esac ;;
	--gcloud_backup_user)
		case $2 in
		"") echo "No gcloud backup user provided, exiting"; exit -1; shift 2 ;;
		*) GCLOUD_BACKUP_USER="$2"; shift 2 ;;
		esac ;;
	--) shift ; break ;;
        *) echo "Internal error!" ; exit 1 ;;
    esac
done

if [[ "$NIGHTLY" -eq 0 && "$WEEKLY" -eq 0 && "$GCLOUD_SETUP" -eq 0 ]]; then
	echo "Either nightly, weekly or setup needs to be set for the backupscript to run"
	echo "EXITING!"
	exit -1
fi

MAINTINANCE_USER=SuperUser
ETH_ADAPTER=eth0
export P4PASSWD="$TICKET"
NOTIFICATION_RECIPIENTS=""
export P4ROOT=/mnt/PerforceLive/root
IP_ADDR=`ip a s ${ETH_ADAPTER} | grep -E -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d' ' -f2`
export P4PORT=$IP_ADDR:1666
export P4USER=$MAINTINANCE_USER

# Ensure that we can quit in the middle of a function by running exit 1 if we catches the TERM signal
trap "exit 1" TERM
export TOP_PID=$$

# Helper function to make it easier to read when we are force quitting the script
function force_exit() {
	# Send the TERM signal
	kill -s TERM $TOP_PID
}

function force_exit_msg() {
	MESSAGE="$1"
	sendmail "${MESSAGE}"
	echoerr "${MESSAGE}"
	force_exit
}

function sendmail() {
	MESSAGE="$1"
	echo -e "From: Perforce Server\nSubject: Perforce server backup failed\n\n${MESSAGE}" | ssmtp ${NOTIFICATION_RECIPIENTS}
}

function safe_command() {
	local COMMAND="$1"
	local PRINT_RESULT=false
	if [[ "$#" == 2 ]]; then
		PRINT_RESULT=$2
	fi

	declare -I COMMAND_OUTPUT
	COMMAND_OUTPUT=$(eval "$COMMAND 2>&1")
	check_returncode_with_msg $? "Failed to run: '${COMMAND}' with error:\n${COMMAND_OUTPUT}"
	if [[ "$PRINT_RESULT" = true ]]; then
		echo -e "${COMMAND_OUTPUT}"
	fi
}

function safe_gcloud() {
	local COMMAND="$1"
	local PRINT_RESULT=false
	if [[ "$#" == 2 ]]; then
		PRINT_RESULT="$2"
	fi

	safe_command "gcloud $COMMAND -q" "${PRINT_RESULT}"
}

# ability to use echoerr "Error message" to print to stderr instead of stdout
function echoerr() { echo -e "$@" 1>&2; }

# checks if a element is present in a array. Ensure that both parameters passed in is enclosed
#	in ""
# @param 1 the element to check if it's present in the array
# @param 2 the array to check in
function contains_element() {
	local ITR TO_MATCH="$1"
	shift

	for ITR; do [[ "$ITR" == "$TO_MATCH" ]] && return 0; done
	return 1
}

# Helper function to get p4 config values, takes 1-2 parameters
# @param 1 The variable we want to pass to p4 configure show
# @param 2 if false, we are not operating in strict mode, and will not terminate the
#       application if the config variable doesn't exist
function get_p4config_value() {
        # parse input
        local CONFIG_VAR="$1"
        local STRICT=true
        if [[ $# == 2 ]]; then
                STRICT=$2
        fi

        # Get config value
        local CONFIG_OUTPUT=`p4 configure show ${CONFIG_VAR} 2>&1`
        # if the above command output contains "No configurables have been set for server", then
        # we it's a error. Can't use return value as it's always 0

	local ERROR_STRINGS=("Your session has expired, please login again."
		"Perforce password (P4PASSWD) invalid or unset.")

	contains_element "${CONFIG_OUTPUT}" "${ERROR_STRINGS[@]}"
	if [[ $? == 0 || "$CONFIG_OUTPUT" == *"No configurables have been set for server"* ]]; then
		local ERROR_MSG="Failed to get p4 configure variable ${CONFIG_VAR} with error: '${CONFIG_OUTPUT}'"
        if [[ $STRICT ]]; then
			force_exit_msg "${ERROR_MSG}"
		else
			echoerr "${ERROR_MSG}"
		fi
		return -1
	fi

        # p4 configure show return multiple lines, with the hierarchy of how the variable was set, with the first
        # output having the highest prioerty, so just get the first line and strip away everything before = sign
        local OUTPUT_WITH_SOURCE=`cut -d "=" -f2- <<< ${CONFIG_OUTPUT} | head -n 1`
        # now the variable might end with " (default)", " (configure)", " (-p)", (-v) or (serverid) to show
        # where it comes from, strip that
        echo ${OUTPUT_WITH_SOURCE%% (*)}
        return 0
}

function check_returncode_with_msg() {
	RETURN_CODE=$1
	ERROR_MESSAGE="$2"

	if [[ "${RETURN_CODE}" -ne 0 ]]; then
		force_exit_msg "${ERROR_MESSAGE}"
	fi
}


if [[ "$GCLOUD_SETUP" -eq 1 ]]; then
	echo "Running SETUP"
	if [[ "${GCLOUD_USER}" == "-1" ]]; then
		force_exit_msg "gcloud_setup failed: --gcloud_setup requires --gcloud_user to be passed"
	fi
	if [[ "${GCLOUD_PROJECT}" == "-1" ]]; then
		force_exit_msg "gcloud_setup failed: --gcloud_setup requires --gcloud_project to be passed"
	fi
	if [[ "${GCLOUD_BUCKET}" == "-1" ]]; then
		force_exit_msg "gcloud_setup failed: --gcloud_setup requires --gcloud_bucket to be passed"
	fi
	if [[ "${GCLOUD_BACKUP_USER}" == "-1" ]]; then
		force_exit_msg "gcloud_setup failed: --gcloud_setup requires --gcloud_backup_user to be passed"
	fi

	declare -I GCLOUD_OUTPUT

	# Check if the user is already logged in
	GCLOUD_OUTPUT=$(safe_gcloud "auth list --filter-account=${GCLOUD_USER}" true)

	# Need to login, so run interactive prompt (don't use safe_gcloud or safe_command)
	if [[ "${GCLOUD_OUTPUT}" == *"No credentialed accounts."* ]]; then
		gcloud auth login ${GCLOUD_USER}
		check_returncode_with_msg "$?" "gcloud_setup failed: Failed to login"
	else
		# Set the active account
		safe_gcloud "config set account ${GCLOUD_USER}" true
	fi

	# Ensure that we are working on the correct project
	GCLOUD_OUTPUT=$(safe_gcloud "config set project ${GCLOUD_PROJECT}" true)
	if [[ "${GCLOUD_OUTPUT}" == *"WARNING: You do not appear to have access to project [${GCLOUD_PROJECT}] or it does not exist."* ]]; then
		force_exit_msg "gcloud_setup failed: You don't have permission or the project ${GCLOUD_PROJECT} doesn't exist: Error: \n'${GCLOUD_OUTPUT}'"
	fi

	# check if the bucket exists
	GCLOUD_OUTPUT=$(safe_gcloud "storage buckets list --filter=${GCLOUD_BUCKET}")
	# Bucket doesn't exist, create it
	if [[ "$GCLOUD_OUTPUT" == *"Listed 0 items."* ]]; then
		safe_gcloud "storage buckets create gs://${GCLOUD_BUCKET}/ \
		--uniform-bucket-level-access \
		--default-storage-class=Standard \
		--location=EUROPE-NORTH1 \
		--pap \
		2>&1" true
	fi

	# The required permission of the backup role
	#local REQUIRED_PERMISSIONS=

	# Check if the role exists
	gcloud iam roles describe ${GCLOUD_BACKUP_ROLE} --project=${GCLOUD_PROJECT} > /dev/null
	
	# If the backup role doesn't exist, create it
	if [[ "$?" -eq "1" ]]; then
		safe_gcloud "iam roles create ${GCLOUD_BACKUP_ROLE} --project=${GCLOUD_PROJECT}" true
	else
		echo "Ensure that the role has the correct permissions"
	fi

	GCLOUD_OUTPUT=`gcloud iam service-accounts list --format=json` # --filter=${GCLOUD_BACKUP_USER} 2>&1`
	#if [[ "$GCLOUD_OUTPUT" == "Listed 0 items." ]]
	echo "GCLOUD_OUTPUT WAS '${GCLOUD_OUTPUT}' RESULT WAS $?"

	#safe_gcloud "auth login --cred-file=/etc/backup/creds/perforce_backup.json 2>&1" true 
	#safe_gcloud "config set project ninjagarden-406616" true
	force_exit
fi

if [[ "$NIGHTLY" -eq 1 ]]; then
	# Reference: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup-procedure.html
	# Nightly backup
	# 1. Make checkpoint
	CHECKPOINT_OUTPUT=`p4d -jc -z 2>&1`

	# 2. Ensure the checkpointing was successful
	check_returncode_with_msg $? "Failed to make a checkpoint, output was\n${CHECKPOINT_OUTPUT}"

	PARSE_MD5_SED_CMD='s/^MD5 \(.+\) = (.+)$/\1/p'

	JOURNAL_BACKUP_FILE=`sed -nE 's/^Checkpointing to (.+)...$/\1/p' <<< ${CHECKPOINT_OUTPUT}`
	CHECKPOINT_REPORTED_MD5=`sed -nE "${PARSE_MD5_SED_CMD}" <<< ${CHECKPOINT_OUTPUT}`

	JOURNAL_FILE=$(get_p4config_value P4JOURNAL)

	JOURNAL_PREFIX=$(get_p4config_value journalPrefix)
	JOURNAL_DIR="${JOURNAL_FILE%/*}"
	
	# Validate journal file
	VALIDATE_JOURNAL_OUTPUT=`p4d -jv "${P4ROOT}/${JOURNAL_BACKUP_FILE}" 2>&1`
	check_returncode_with_msg $? "Failed validating journal backup, output was:\n${VALIDATE_JOURNAL_OUTPUT}"
	# 3. Confirm checkpoint was correctly written to disk with md5
	gzip -dk "${P4ROOT}/${JOURNAL_BACKUP_FILE}"

	JOURNAL_BACKUP_FILE_WITHOUT_GZ=${P4ROOT}/${JOURNAL_BACKUP_FILE%.gz}
	MD5_FILE_CONTENT=`cat "${JOURNAL_BACKUP_FILE_WITHOUT_GZ}.md5" | sed -nE "${PARSE_MD5_SED_CMD}"`
	if [[ "${MD5_FILE_CONTENT^^}" != "${CHECKPOINT_REPORTED_MD5^^}" ]]; then
		force_exit_msg "MD5 file has become corrupted during write! Aborting backup"
	fi

	MD5_OF_CHECKPOINT=`md5sum ${JOURNAL_BACKUP_FILE_WITHOUT_GZ} | awk '{print $1}'`

	if [[ "${MD5_OF_CHECKPOINT^^}" != "${MD5_FILE_CONTENT^^}" ]]; then
	force_exit_msg "Checkpoint file has become corrupted during write! Aborting backup"
	fi

	# Remove the extracted file that we used to verify the md5 of
	rm -f "${JOURNAL_BACKUP_FILE_WITHOUT_GZ}"

	# 4. Trim down amount of checkpoints stored locally on the server
	

	# 5. Backup
	# Set correct project in google cloud
	GCLOUD_OUTPUT=`gcloud config set project ninjagarden-406616 2>&1`
	check_returncode_with_msg "$?" "Failed to set project id in gcloud with error\n${GCLOUD_OUTPUT}"

	#GSUTIL_OUTPUT=$(gsutil -m rsync -d -r "${P4ROOT}/${JOURNAL_DIR}" gs://feeblemindstestbackup/journals 2>&1)
	#check_returncode_with_msg "$?" "Backup to gcloud failed with error:\n ${GSUTIL_OUTPUT}"
	#echo "GSUTIL_OUTPUT=${GSUTIL_OUTPUT}"
	# 	checkpoint + md5
	#	rotated journal file
	#	license file
	#	versioned files
	# 6. backup the server.id

	echo "Nightly backup succeeded"
fi

if [[ "$WEEKLY" -eq 1 ]]; then
	# Recommended weekly verify
	# 1. Verify archive files (p4 verify -q //...)
	VERIFY_OUTPUT=$(p4 verify -q //... 2>&1)
	RESULT=$?
	check_returncode_with_msg ${RESULT} "Verifying files failed with errormessage:\n${VERIFY_OUTPUT}"
	# 2. Verify shelved files 
	VERIFY_OUTPUT=$(p4 verify -q -S //... 2>&1)
	RESULT=$?
	check_returncode_with_msg ${RESULT} "Verifying shelved files failed with errormessage:\n${VERIFY_OUTPUT}"

	echo "Weekly backup succeeded"
fi
