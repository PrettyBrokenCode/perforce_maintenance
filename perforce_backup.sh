#!/bin/bash

TEMP=$(getopt -o v,m,n,w,t:,u: -l no_revoke,verbose,p4_user:,mail:,gcloud_backup_role:,gcloud_user:,gcloud_setup,gcloud_bucket:,gcloud_project:,gcloud_backup_user:,nightly,weekly,ticket: -- "$@")
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

NOTIFICATION_RECIPIENTS=-1
MAINTINANCE_USER=SuperUser
TICKET=-1

VERBOSE=0
NO_REVOKE=0

NIGHTLY=0
WEEKLY=0

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
		-v|--verbose) VERBOSE=1; shift ;;
		--no_revoke) NO_REVOKE=1; shift ;;
	-m|--mail)
		case $2 in
			"") echo "No mail provided, discarding parameter"; shift 2 ;;
			*) NOTIFICATION_RECIPIENTS="$2"; shift 2 ;;
		esac ;;
	-u|--p4_user)
		case $2 in
			"") echo "No p4 user provided, discarding parameter"; shift 2 ;;
			*) MAINTINANCE_USER="$2"; shift 2 ;;
		esac ;;

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

ETH_ADAPTER=eth0
export P4PASSWD="$TICKET"
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

function verbose_log() {
	local MESSAGE="$1"
	if [[ "$VERBOSE" -ne 0 ]]; then
		echo -e "$MESSAGE"
	fi
}

function force_exit_msg() {
	local MESSAGE="$1"

	sendmail "${MESSAGE}"
	echoerr "${MESSAGE}"

	force_exit
}

function is_root() {
	local OUTPUT=`whoami`

	if [[ "${OUTPUT}" == "root" ]]; then
		return 1
	fi

	return 0
}

function sendmail() {
	local MESSAGE="$1"

	# Verify that we have specified the notification recipient
	if [[ "$NOTIFICATION_RECIPIENTS" != -1 ]]; then
		echo -e "From: Perforce Server\nSubject: Perforce server backup failed\n\n${MESSAGE}" | ssmtp ${NOTIFICATION_RECIPIENTS}
	else
		verbose_log "No notification recipient specified, no mail sent"
	fi
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
	local RETURN_CODE=$1
	local ERROR_MESSAGE="$2"

	if [[ "${RETURN_CODE}" -ne 0 ]]; then
		force_exit_msg "${ERROR_MESSAGE}"
	fi
}

function get_backup_account_mail() {
	require_param "GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "GCLOUD_PROJECT" "--gcloud_project"

	echo "${GCLOUD_BACKUP_USER}@${GCLOUD_PROJECT}.iam.gserviceaccount.com"
}

function get_backup_role_absolute_path() {
	require_param "GCLOUD_PROJECT" "--gcloud_project"
	require_param "GCLOUD_BACKUP_ROLE" "--gcloud_backup_role"

	echo "projects/${GCLOUD_PROJECT}/roles/${GCLOUD_BACKUP_ROLE}"
}

function backup_account_cred_file() {
	echo "/opt/perforce/backup_key.json"
}

# from https://stackoverflow.com/a/62757929
function callstack() { 
	local i=1 max_depth=-1 line file func skip_first
	# First parameter determines how many layers of callers we want to skip at start
	if [[ "$#" -ge 1 ]]; then
		i="$1"
	fi
	if [[ "$#" -ge 2 ]]; then
		max_depth="$2"
	fi

	while read -r line func file < <(caller $i); do
		echo >&2 "[$i] $file:$line $func(): $(sed -n ${line}p $file)"

		if [[ "$max_depth" -ne "-1" && "$i" -ge "$max_depth" ]]; then
			break
		fi

		((i++))
	done
}

function show_var() {
	local VARNAME=$1

	echo -e "${VARNAME}='${!VARNAME}'"
}

function from_func() {
	cut -d ' ' -f 2 <<< `caller 1`
}

function require_param() {
	local VARNAME="$1"
	local PARAMETER_NAME="$2"

	if [[ "${!VARNAME}" == "-1" || "${!VARNAME}" == "" ]]; then
		force_exit_msg "$(from_func) failed: reqires ${PARAMETER_NAME} to be passed"
	fi
}


function gcloud_setup() {
	verbose_log "Running SETUP"

	require_param "GCLOUD_USER"			"--gcloud_user"
	require_param "GCLOUD_PROJECT"		"--gcloud_project"
	require_param "GCLOUD_BUCKET" 		"--gcloud_bucket"
	require_param "GCLOUD_BACKUP_USER" 	"--gcloud_backup_user"
	require_param "GCLOUD_BACKUP_ROLE" 	"--gcloud_backup_role"

	declare -I GCLOUD_OUTPUT

	# Check if the user is already logged in
	GCLOUD_OUTPUT=$(safe_gcloud "auth list --filter-account=${GCLOUD_USER} --format=json" true)

	# Need to login, so run interactive prompt (don't use safe_gcloud or safe_command)
	if  [[ $(echo -e "${GCLOUD_OUTPUT}" | jq length) -eq "0" ]]; then
		gcloud auth login ${GCLOUD_USER}
		check_returncode_with_msg "$?" "gcloud_setup failed: Failed to login"
	else
		verbose_log "Setting account ${GCLOUD_USER}"
		# Set the active account
		safe_gcloud "config set account ${GCLOUD_USER}" true
	fi

	# Ensure that we are working on the correct project
	GCLOUD_OUTPUT=$(safe_gcloud "config set project ${GCLOUD_PROJECT}" true)

	if [[ "${GCLOUD_OUTPUT}" == *"WARNING: You do not appear to have access to project [${GCLOUD_PROJECT}] or it does not exist."* ]]; then
		force_exit_msg "gcloud_setup failed: You don't have permission or the project ${GCLOUD_PROJECT} doesn't exist: Error: \n'${GCLOUD_OUTPUT}'"
	fi

	# check if the bucket exists
	GCLOUD_OUTPUT=$(safe_gcloud "storage buckets list --filter=${GCLOUD_BUCKET} --format=json" true)

	# Bucket doesn't exist, create it
	if  [[ $(echo -e "${GCLOUD_OUTPUT}" | jq length) -eq 0 ]]; then
		echo "Creating bucket"
		safe_gcloud "storage buckets create gs://${GCLOUD_BUCKET}/ \
		--uniform-bucket-level-access \
		--default-storage-class=Standard \
		--location=EUROPE-NORTH1 \
		--pap \
		2>&1" true
	else
		echo "Skipping creating bucket, as it already exists"
	fi

	# The required permission of the backup role
	local REQUIRED_PERMISSIONS="storage.objects.list,storage.objects.create,storage.objects.delete,storage.objects.get"

	# Check if the role exists
	gcloud iam roles describe ${GCLOUD_BACKUP_ROLE} --project=${GCLOUD_PROJECT} > /dev/null
	
	# If the backup role doesn't exist, create it
	if [[ "$?" -eq "1" ]]; then
		# @TODO: Verify that permissions are set correctly
		verbose_log "Creating backup role with correct permissions"
		safe_gcloud "iam roles create $GCLOUD_BACKUP_ROLE --project=$GCLOUD_PROJECT --permissions=$REQUIRED_PERMISSIONS" true
	else
		verbose_log "Updating backup role with correct permissions"
		safe_gcloud "iam roles update $GCLOUD_BACKUP_ROLE --project=$GCLOUD_PROJECT --permissions=$REQUIRED_PERMISSIONS" true
	fi

	GCLOUD_OUTPUT=`gcloud iam service-accounts list --format=json --filter=$(get_backup_account_mail) 2>&1`

	if [[ $(echo -e "${GCLOUD_OUTPUT}" | jq length) -eq 0 ]]; then
		# User doesn't exist, create it
		safe_gcloud "iam service-accounts create ${GCLOUD_BACKUP_USER} --display-name=\"Perforce backup user\"" true
	else
		echo "@TODO: Updating service account"
	fi

	# Get the roles of the service account to verify that the service account has the correct role
	GCLOUD_OUTPUT=$(safe_gcloud "projects get-iam-policy ${GCLOUD_PROJECT} --flatten='bindings[].members' \
		--format='table(bindings.role)' \
		--filter='bindings.members:serviceAccount:$(get_backup_account_mail) AND \
			bindings.role=$(get_backup_role_absolute_path)' --format=json" true)

	if [[ $(echo -e "${GCLOUD_OUTPUT}" | jq length) -eq 0 ]]; then
		# Add the role to the service account
		verbose_log "Adding the role $(get_backup_role_absolute_path) to backup user $(get_backup_account_mail)"
		safe_gcloud "projects add-iam-policy-binding ${GCLOUD_PROJECT} \
			--role=$(get_backup_role_absolute_path) \
			--member=serviceAccount:$(get_backup_account_mail)" true
	else
		echo "Skipping adding role to backup user, as it already has it"
	fi

	if [[ ! -d /opt/perforce ]]; then
		safe_command "mkdir /opt/perforce/" true
	fi

	# @TODO: Check if the key if for the current backup user, and if not, delete old key and download a new key
	if [[ ! -f "$(backup_account_cred_file)" ]]; then
		verbose_log "Downloading credentials file for service-account"
		safe_gcloud "iam service-accounts keys create $(backup_account_cred_file) --iam-account=$(get_backup_account_mail)" true
		chmod 600 /opt/perforce/backup_key.json
	fi

	if [[ "$NO_REVOKE" -ne "0" ]]; then
		# Revoke our credentials so that they don't stay on the server by accident
		safe_gcloud "auth revoke ${GCLOUD_USER}"
	fi

	force_exit
}

function nightly_backup() {
	# Reference: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup-procedure.html
	# Nightly backup

	require_param "GCLOUD_PROJECT" "--gcloud_project"
	require_param "GCLOUD_BUCKET" "--gcloud_bucket"
	require_param "GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "TICKET" "-t|--ticket"


	P4ROOT=$(get_p4config_value P4ROOT)
	eval "export P4ROOT=$P4ROOT"

	JOURNAL_FILE=$(get_p4config_value P4JOURNAL)
	JOURNAL_PREFIX=$(get_p4config_value journalPrefix)
	JOURNAL_DIR="${JOURNAL_FILE%/*}"

	ARCHIVES_DIR=$(get_p4config_value server.depot.root)
	
	# 1. Make checkpoint and ensure that it was successful
	verbose_log "Making checkpoint..."
	CHECKPOINT_OUTPUT=$(safe_command "p4d -jc -z" true)

	# 2. Ensure the checkpointing was successful
	PARSE_MD5_SED_CMD='s/^MD5 \(.+\) = (.+)$/\1/p'

	JOURNAL_BACKUP_FILE=`sed -nE 's/^Checkpointing to (.+)...$/\1/p' <<< ${CHECKPOINT_OUTPUT}`
	CHECKPOINT_REPORTED_MD5=`sed -nE "${PARSE_MD5_SED_CMD}" <<< ${CHECKPOINT_OUTPUT}`
	
	verbose_log "Validating journal file was correctly written to disk..."
	# Validate journal file
	safe_command "p4d -jv \"${P4ROOT}/${JOURNAL_BACKUP_FILE}\"" false
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
	verbose_log "Authenticating with google cloud storage..."
	safe_gcloud "auth login $(get_backup_account_mail) --cred-file=$(backup_account_cred_file)" true
	safe_gcloud "config set project ${GCLOUD_PROJECT}"

	verbose_log "Sending journals and checkpoints to google cloud..."
	# 	checkpoint + md5, rotated journal file
	safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "${P4ROOT}/${JOURNAL_DIR}" gs://${GCLOUD_BUCKET}/journals" true
	#	license file
	verbose_log "Sending license to google cloud..."
	safe_gcloud "storage cp "${P4ROOT}/license" gs://${GCLOUD_BUCKET}/license" true
	#	versioned files
	verbose_log "Sending content to google cloud..."
	safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "${P4ROOT}/${ARCHIVES_DIR}" gs://${GCLOUD_BUCKET}/archives" true

	# 6. backup the server.id
	verbose_log "Sending server.id to google cloud..."
	safe_gcloud "storage cp "${P4ROOT}/server.id" gs://${GCLOUD_BUCKET}/server.id" true

	verbose_log "Nightly backup succeeded"
}

function weekly_verification() {
	require_param "TICKET" "-t|--ticket"

	# 1. Verify archive files
	safe_command "p4 verify -q //..."
	# 2. Verify shelved files 
	safe_command "p4 verify -q -S //..."

	verbose_log "Weekly verification succeeded"
}

if [[ "$GCLOUD_SETUP" -eq 1 ]]; then
	gcloud_setup
fi

if [[ "$NIGHTLY" -eq 1 ]]; then
	nightly_backup
fi

if [[ "$WEEKLY" -eq 1 ]]; then
	weekly_verification
fi
