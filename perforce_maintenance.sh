#!/bin/bash

# ability to use echoerr "Error message" to print to stderr instead of stdout
function echoerr() { echo -e "$@" 1>&2; }

TEMP=$(getopt -o v,m:,n,w,t:,s,u:,r:,i -l p4_tcp_port:,p4_adapter:,checkpoint_max_age:,checkpoint_min_number:,no_revoke,verbose,p4_user:,mail:,gcloud_backup_role:,gcloud_user:,gcloud_setup,gcloud_bucket:,gcloud_project:,gcloud_backup_user:,nightly,weekly,p4_ticket:,setup,mail_sender:,mail_token:,server_name:,restore:,p4_root:,p4_journal:,p4_windows_case,p4_archive_dir:,no_fetch_license,interactive -- "$@")
if [ $? != 0 ] ; then echoerr "Terminating..." ; exit 1 ; fi

eval set -- "$TEMP"

_NOTIFICATION_RECIPIENTS=-1
_SERVER_NAME=-1

_P4_USER=SuperUser
_P4_TICKET=-1
_P4_ROOT=-1
_P4_JOURNAL=-1
_P4_CASE="-C0"
_P4_ARCHIVES_DIR=-1
_P4_TCP_PORT=1666
_P4_ADAPTER=-1

_FETCH_LICENSE=true
_VERBOSE=0
_NO_REVOKE=0
_INTERACTIVE=0

_NIGHTLY=0
_WEEKLY=0
_SETUP=0
_RESTORE=0

_MAINTENENCE_CHECKPOINT_MIN_NUM=14
_MAINTENENCE_CHECKPOINT_MAX_AGE_IN_DAYS=31

_MAIL_SENDER=-1
_MAIL_TOKEN=-1

_GCLOUD_SETUP=0

_GCLOUD_USER=-1
_GCLOUD_BUCKET=-1
_GCLOUD_PROJECT=-1
_GCLOUD_BACKUP_ROLE=CloudBackupRole
_GCLOUD_BACKUP_USER=-1

while true; do
	case "$1" in
		-n|--nightly) _NIGHTLY=1; shift ;;
		-w|--weekly) _WEEKLY=1; shift ;;
		-i|--interactive) _INTERACTIVE=1; shift ;;
		--gcloud_setup) _GCLOUD_SETUP=1; shift ;;
		-v|--verbose) _VERBOSE=1; shift ;;
		--no_revoke) _NO_REVOKE=1; shift ;;
		-s|--setup) _SETUP=1; shift ;;
		--p4_windows_case) _P4_CASE="-C1"; shift ;;
		--no_fetch_license) _FETCH_LICENSE=false; shift ;;
		-r|--restore)
			case $2 in
				"") force_exit_msg "No restore mode provided, please provide 'db' or 'db_and_files', EXITING"; shift 2 ;;
				db|db_and_files) _RESTORE="$2"; shift 2 ;;
				*) force_exit_msg "Unknown restoration mode '$2', please provide 'db' or 'db_and_files', EXITING"; shift 2 ;;
			esac ;;
		--p4_root)
			case $2 in
				"") echo "No P4ROOT provided, discarding parameter"; shift 2 ;;
				*) _P4_ROOT="$2"; shift 2 ;;
			esac ;;
		--p4_tcp_port)
			case $2 in
				"") echo "No tcp-port provided, discarding parameter"; shift 2 ;;
				*) _P4_TCP_PORT="$2"; shift 2 ;;
			esac ;;
		--p4_adapter)
			case $2 in
				"") echo "No adapter provided, discarding parameter"; shift 2 ;;
				*) _P4_ADAPTER="$2"; shift 2 ;;
			esac ;;
		--checkpoint_max_age)
			case $2 in
				"") echo "No max age for checkpoints provided, discarding parameter"; shift 2 ;;
				*) _MAINTENENCE_CHECKPOINT_MAX_AGE_IN_DAYS="$2"; shift 2 ;;
			esac ;;
		--checkpoint_min_number)
			case $2 in
				"") echo "No minimum number of checkpoints specified, discarding parameter"; shift 2 ;;
				*) _MAINTENENCE_CHECKPOINT_MIN_NUM="$2"; shift 2 ;;
			esac ;;
		--p4_archive_dir)
			case $2 in
				"") echo "No P4 ARCHIVES DIR provided (server.depot.root), discarding parameter"; shift 2 ;;
				*) _P4_ARCHIVES_DIR="$2"; shift 2 ;;
			esac ;;
		--p4_journal)
			case $2 in
				"") echo "No P4JOURNAL provided, discarding parameter"; shift 2 ;;
				*) _P4_JOURNAL="$2"; shift 2 ;;
			esac ;;
		-m|--mail)
			case $2 in
				"") echo "No mail receiver provided, discarding parameter"; shift 2 ;;
				*) _NOTIFICATION_RECIPIENTS="$2"; shift 2 ;;
			esac ;;
		--mail_sender)
			case $2 in
				"") echo "No mail provided, discarding parameter"; shift 2 ;;
				*) _MAIL_SENDER="$2"; shift 2 ;;
			esac ;;
		--mail_token)
			case $2 in
				"") echo "No mail token provided, discarding parameter"; shift 2 ;;
				*) _MAIL_TOKEN="$2"; shift 2 ;;
			esac ;;
		-u|--p4_user)
			case $2 in
				"") echo "No p4 user provided, discarding parameter"; shift 2 ;;
				*) _P4_USER="$2"; shift 2 ;;
			esac ;;
		--server_name)
			case $2 in
				"") echo "No server name provided, discarding parameter"; shift 2 ;;
				*) _SERVER_NAME="$2"; shift 2 ;;
			esac ;;
		-t|--p4_ticket) 
			case $2 in
				"") echo "No ticket provided, discarding parameter"; shift 2 ;;
				*) _P4_TICKET="$2"; shift 2 ;;
			esac ;;
		--gcloud_user)
			case $2 in
				"") echo "No gcloud user provided, exiting"; exit -1; shift 2 ;;
				*) _GCLOUD_USER="$2"; shift 2 ;;
			esac ;;
		--gcloud_bucket)
			case $2 in
				"") echo "No gcloud bucket provided, exiting"; exit -1; shift 2 ;;
				*) _GCLOUD_BUCKET="$2"; shift 2 ;;
			esac ;;
		--gcloud_project)
			case $2 in
				"") echo "No gcloud provided provided, exiting"; exit -1; shift 2 ;;
				*) _GCLOUD_PROJECT="$2"; shift 2 ;;
			esac ;;
		--gcloud_backup_role)
			case $2 in
				"") echo "No gcloud backup role provided, exiting"; exit -1; shift 2 ;;
				*) _GCLOUD_BACKUP_ROLE="$2"; shift 2 ;;
			esac ;;
		--gcloud_backup_user)
			case $2 in
				"") echo "No gcloud backup user provided, exiting"; exit -1; shift 2 ;;
				*) _GCLOUD_BACKUP_USER="$2"; shift 2 ;;
			esac ;;
		--) shift ; break ;;
		*) echoerr "Internal error!, received unknown token '$1'" ; exit 1 ;;
    esac
done

if [[ "$_NIGHTLY" -eq 0 && "$_WEEKLY" -eq 0 && "$_GCLOUD_SETUP" -eq 0 && "$_SETUP" -eq 0 && "$_RESTORE" -ne 0 && "$_INTERACTIVE" -ne 0 ]]; then
	echoerr "Either nightly, weekly, setup, restore or weekly_setup needs to be set for the backupscript to run"
	echoerr "EXITING!"
	exit -1
fi

# Ensure that we can quit in the middle of a function by running exit 1 if we catches the TERM signal
trap "exit 1" TERM
export TOP_PID=$$

# Helper function to make it easier to read when we are force quitting the script
function force_exit() {
	# Send the TERM signal
	kill -s TERM $TOP_PID
}

# from https://stackoverflow.com/a/62757929
function callstack() { 
	local i=${1:-1}; shift
	local max_depth=${1:--1}; shift
	local line file func skip_first

	while read -r line func file < <(caller $i); do
		if [[ "$max_depth" -ne "-1" && "$i" -ge "$max_depth" ]]; then
			break
		fi

		echo "[$i] $file:$line $func(): $(sed -n ${line}p $file)"

		((i++))
	done
}

function verbose_log() {
	local MESSAGE="$1"
	if [[ "$_VERBOSE" -ne 0 ]]; then
		echo -e "$MESSAGE"
	fi
}

function force_exit_msg() {
	local MESSAGE="$1"

	echoerr "$MESSAGE"
	send_mail "$MESSAGE"

	force_exit
}

function is_root() {
	local OUTPUT=`whoami`

	if [[ "$OUTPUT" == "root" ]]; then
		return 1
	fi

	return 0
}

function send_mail() {
	local MESSAGE="$1"

	# Verify that we have specified the notification recipient
	if [[ "$_NOTIFICATION_RECIPIENTS" != -1 ]]; then
		echo -e "From: Perforce Server\nSubject: Perforce server backup failed\n\n$MESSAGE" | ssmtp $_NOTIFICATION_RECIPIENTS
	else
		verbose_log "No notification recipient specified, no mail sent"
	fi
}

function get_config_file() {
	echo "/opt/perforce/backup/maintenance_conf.json"
}

function safe_command() {
	local COMMAND="$1"; shift
	local PRINT_RESULT=${1:-false}

	# Declare local variable that doesn't change the $?
	declare -I COMMAND_OUTPUT
	COMMAND_OUTPUT=$(eval "$COMMAND 2>&1")
	check_returncode_with_msg $? "Failed to run: '$COMMAND' with error:\n$COMMAND_OUTPUT\n$(callstack)"
	if [[ $PRINT_RESULT = true ]]; then
		echo -e "$COMMAND_OUTPUT"
	fi
}

function safe_command_as() {
	local COMMAND="$1"; shift
	local USER="$1"; shift
	local PRINT_RESULT=${1:-false}

	local USER_SWITCH_COMMAND=""
	if [[ "$(whoami)" != "$USER" ]]; then
		USER_SWITCH_COMMAND="sudo -u $USER"
	fi

	safe_command "$USER_SWITCH_COMMAND $COMMAND" "$PRINT_RESULT"
}

function gc_safe_gcloud() {
	local COMMAND="$1";	shift
	local PRINT_RESULT=${1:-false}

	safe_command "gcloud $COMMAND -q" "$PRINT_RESULT"
}

function gc_create_bucket_if_not_exist() {
	local BUCKET="$1"; shift

	# check if the bucket exists
	local GCLOUD_OUTPUT=$(gc_safe_gcloud "storage buckets list --filter=$BUCKET --format=json" true)

	# Bucket doesn't exist, create it
	if  [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		verbose_log "Creating bucket"
		gc_safe_gcloud "storage buckets create gs://$BUCKET/ \
		--uniform-bucket-level-access \
		--default-storage-class=Standard \
		--location=EUROPE-NORTH1 \
		--pap \
		2>&1" true
	else
		verbose_log "Skipping creating bucket, as it already exists"
	fi

	return 0
}

function gc_login() {
	local USER="$1"; shift
	local STRICT=${1:-true}

	# Check if the user is already logged in
	local GCLOUD_OUTPUT=$(gc_safe_gcloud "auth list --filter-account=$USER --format=json" false)

	# Need to login, so run interactive prompt (don't use gc_safe_gcloud or safe_command)
	if  [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq "0" ]]; then
		gcloud auth login $USER
		if [[ "$?" -ne 0 ]]; then
			if $STRICT; then
				force_exit_msg "gc_login failed: Failed to login"
			else
				echo "gc_login failed: Failed to login"
				return 1
			fi
		fi
	else
		verbose_log "Setting account $USER"
		# Set the active account
		gc_safe_gcloud "config set account $USER"
	fi

	return 0
}

function gc_create_or_update_backup_role() {
	local BACKUP_ROLE="$1"; shift

	# The required permission of the backup role
	local REQUIRED_PERMISSIONS="storage.objects.list,storage.objects.create,storage.objects.delete,storage.objects.get,storage.buckets.get"
	local ROLE_COMMAND="$BACKUP_ROLE --project=$_GCLOUD_PROJECT --permissions=$REQUIRED_PERMISSIONS --stage=ALPHA"

	# Check if the role exists
	gcloud iam roles describe $BACKUP_ROLE --project=$_GCLOUD_PROJECT &> /dev/null
	
	# If the backup role doesn't exist, create it
	if [[ "$?" -eq "1" ]]; then
		verbose_log "Creating backup role with correct permissions"
		gc_safe_gcloud "iam roles create $ROLE_COMMAND"
	else
		verbose_log "Updating backup role with correct permissions"
		gc_safe_gcloud "iam roles update $ROLE_COMMAND"
	fi
}

function gc_create_or_update_backup_user() {
	local GCLOUD_BACKUP_USER="$1"

	local GCLOUD_OUTPUT=`gcloud iam service-accounts list --format=json --filter=$(gc_get_backup_account_mail "$GCLOUD_BACKUP_USER") 2>&1`

	if [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		# User doesn't exist, create it
		gc_safe_gcloud "iam service-accounts create $GCLOUD_BACKUP_USER --display-name=\"Perforce backup user\"" true
	else
		verbose_log	"Skipping creating service account as it already exists"
	fi

	# Get the roles of the service account to verify that the service account has the correct role
	GCLOUD_OUTPUT=$(gc_safe_gcloud "projects get-iam-policy $_GCLOUD_PROJECT --flatten='bindings[].members' \
		--format='table(bindings.role)' \
		--filter='bindings.members:serviceAccount:$(gc_get_backup_account_mail "$GCLOUD_BACKUP_USER") AND \
			bindings.role=$(gc_get_backup_role_absolute_path)' --format=json" true)

	if [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		# Add the role to the service account
		verbose_log "Adding the role $(gc_get_backup_role_absolute_path) to backup user $(gc_get_backup_account_mail "$GCLOUD_BACKUP_USER")"
		gc_safe_gcloud "projects add-iam-policy-binding $_GCLOUD_PROJECT \
			--role=$(gc_get_backup_role_absolute_path) \
			--member=serviceAccount:$(gc_get_backup_account_mail "$GCLOUD_BACKUP_USER")" true
	else
		verbose_log "Skipping adding role to backup user, as it already has it"
	fi
}

# @return 0 if the file exists, 1 if it doesn't
function gc_file_exists() {
	local GS_FILE="$1"

	gsutil stat $GS_FILE > /dev/null 2>&1
	return $?
}

function gc_get_bucket_base_path() {
	require_param "_GCLOUD_BUCKET" "--gcloud_bucket"

	local SERVER_NAME=$(p4_get_server_name)

	echo -e "gs://$_GCLOUD_BUCKET/$SERVER_NAME"
}

function gc_get_backup_role_absolute_path() {
	require_param "_GCLOUD_PROJECT" "--gcloud_project"
	require_param "_GCLOUD_BACKUP_ROLE" "--gcloud_backup_role"

	echo "projects/$_GCLOUD_PROJECT/roles/$_GCLOUD_BACKUP_ROLE"
}

function gc_backup_account_cred_file() {
	echo "/opt/perforce/backup/gs_backup_user_key.json"
}


function gc_get_backup_account_mail() {
	local USER=$1

	if [[ "$USER" -eq "-1" || "$USER" == "" ]]; then
		require_param "_GCLOUD_BACKUP_USER" "--gcloud_backup_user"
		USER=$_GCLOUD_BACKUP_USER
	fi
	require_param "_GCLOUD_PROJECT" "--gcloud_project"

	echo "$USER@$_GCLOUD_PROJECT.iam.gserviceaccount.com"
}


# checks if a element is present in a array. Ensure that both parameters passed in is enclosed
#	in ""
# @param 1 the element to check if it's present in the array
# @param 2 the array to check in
function contains_element() {
	local ITR TO_MATCH="$1"; shift

	for ITR; do 
		if [[ "$ITR" == "$TO_MATCH" ]]; then
			return 0; 
		fi
	done
	return 1
}

function get_adapter() {
	echo -e $(ip link show | awk -F: '$0 !~ "wg|lo|vir|wl|^[^0-9]"{sub(/^ /, "", $2); print $2; getline}')
}

function p4_get_port() {
	local ETH_ADAPTER="$_P4_ADAPTER"
	if [[ "$ETH_ADAPTER" -eq "-1" ]]; then
		ETH_ADAPTER=$(get_adapter)
	else
		local EXISTING_ADAPTERS=$(get_adapter)
		mapfile -t EXISTING_ADAPTERS_ARRAY <<< "$EXISTING_ADAPTERS"
		if ! contains_element "$ETH_ADAPTER" "${EXISTING_ADAPTERS_ARRAY[@]}"; then
			force_exit_msg "Non existing ethernet adapter passed in, please pass in a valid adapter with --adapter"			
		fi
	fi

	local NUM_ADAPTERS=$(echo -e "$ETH_ADAPTER" | wc -l)

	if [ "$NUM_ADAPTERS" -gt 1 ]; then
		force_exit_msg "Got more than one ethernet adapter, please pass in --adapter"
	elif [ "$NUM_ADAPTERS" -eq 0 ]; then
		force_exit_msg "Failed to get any ethernet adapter... Check server configuration"
	fi
	local IP_ADDR=`ip a s $ETH_ADAPTER | grep -E -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d' ' -f2`
	echo "$IP_ADDR:$_P4_TCP_PORT"
}

function _p4_internal() {
	require_param "_P4_USER" "--p4_user"
	
	local EXECUTABLE="$1"; shift
	local COMMAND="$1"; shift
	local SAFE="$1"; shift
	local PRINT_RESULT="$1"

	local func_name="safe_command_as"
	if [[ "$SAFE" = false ]]; then
		func_name="run_as"
	fi

	local CAPTURE_STRING="2>&1"
	$func_name "$EXECUTABLE -p $(p4_get_port) -u $_P4_USER $COMMAND $CAPTURE_STRING" "perforce" "$PRINT_RESULT"
}

function p4_run() {
	require_param "_P4_TICKET" "--p4_ticket"

	local COMMAND="$1"; shift
	local SAFE=${1:-true}; shift
	local PRINT_RESULT=${1:-true}

	_p4_internal "p4" "-P $_P4_TICKET $COMMAND" "$SAFE" "$PRINT_RESULT" "$CAPTURE_ALL"
}

function p4d_run() {
	local COMMAND="$1"; shift
	local SAFE=${1:-true}; shift
	local PRINT_RESULT=${1:-true}

	local P4_ROOT=$(p4_get_root)

	_p4_internal "p4d" "-r \"$P4_ROOT\" $COMMAND" "$SAFE" "$PRINT_RESULT" "$CAPTURE_ALL"
}

function p4dctl_run() {
	local ACTION="$1"
	
	if is_root -eq "0" ; then
		force_exit_msg "Require root to control system service helix-p4dctl"
	fi

	case "$ACTION" in
		"start") ;& # Fallthrough
		"stop") ;& # Fallthrough
		"restart") ;;
		*) force_exit_msg "Unknown actions '$ACTION' passed to p4dctl" ;;
	esac
	
	safe_command "systemctl $ACTION helix-p4dctl"
}

function p4_get_root() {
	# Declare local variable that doesn't change the $?
	declare -I P4ROOT
	P4ROOT=$(p4_get_config_value P4ROOT false false)
	if [[ $? != 0 ]]; then	
		require_param "_P4_ROOT" "--p4_root"
		P4ROOT=$_P4_ROOT
	fi
	echo $P4ROOT
}

function p4_get_archives_dir() {
	declare -I ARCHIVES_DIR
	ARCHIVES_DIR=$(p4_get_config_value server.depot.root false false)
	if [[ $? -ne 0 ]]; then
		require_param "_P4_ARCHIVES_DIR" "--p4_archive_dir"
		ARCHIVES_DIR="$_P4_ARCHIVES_DIR"
	fi
	echo -e "$ARCHIVES_DIR"
}

# Helper function to get p4 config values, takes 1-2 parameters
# @param 1 The variable we want to pass to p4 configure show
# @param 2 if false, we are not operating in strict mode, and will not terminate the
#       application if the config variable doesn't exist
# @param 3 if false, then we don't print the output of p4 configure show. Only valid if strict is false
function p4_get_config_value() {
	local CONFIG_VAR="$1"; shift
	local STRICT=${1:-true}; shift
	local PRINT_ERROR=${1:-true}
	
	# Get config value
	local CONFIG_OUTPUT=$(p4_run "configure show $CONFIG_VAR" "$STRICT")
	# if the above command output contains "No configurables have been set for server", then
	# we it's a error. Can't use return value as it's always 0

	local ERROR_STRINGS=("Your session has expired, please login again."
		"Perforce password (P4PASSWD) invalid or unset.")

	local PARTIAL_ERROR_STRINGS=("No configurables have been set for server",
		'Perforce client error: Connect to server failed;')


	# 'Perforce client error: Connect to server failed; check $P4PORT. TCP connect to 10.10.10.211:1666 failed. connect: 10.10.10.211:1666: Connection refused'
	local HAS_ERROR_OUTPUT=false

	case $CONFIG_OUTPUT in
		"Your session has expired, please login again.")			;& # fallthrough
		"Perforce password (P4PASSWD) invalid or unset.")			;& # fallthrough
		*"No configurables have been set for server"*)				;& # fallthrough
		*$'Perforce client error:\n\tConnect to server failed'*)
			HAS_ERROR_OUTPUT=true ;;
	esac

	if [[ $HAS_ERROR_OUTPUT == true ]]; then
		local ERROR_MSG="Failed to get p4 configure variable $CONFIG_VAR with error: '$CONFIG_OUTPUT'"
        if $STRICT; then
			force_exit_msg "$ERROR_MSG"
		else
			if $PRINT_ERROR; then
				echoerr "$ERROR_MSG"
			fi
		fi
		return 1
	fi

	# p4 configure show return multiple lines, with the hierarchy of how the variable was set, with the first
	# output having the highest prioerty, so just get the first line and strip away everything before = sign
	local OUTPUT_WITH_SOURCE=`cut -d "=" -f2- <<< $CONFIG_OUTPUT | head -n 1`
	# now the variable might end with " (default)", " (configure)", " (-p)", (-v) or (serverid) to show
	# where it comes from, strip that
	echo ${OUTPUT_WITH_SOURCE%% (*)}
	return 0
}

function p4_get_journal_dir() {
	declare -I JOURNAL_FILE
	JOURNAL_FILE=$(p4_get_config_value P4JOURNAL false false)
	if [[ $? -ne 0 ]]; then
		require_param "_P4_JOURNAL" "--p4_journal"
		JOURNAL_FILE=$_P4_JOURNAL
	fi

	echo -e "${JOURNAL_FILE%/*}"
}

function p4_get_server_name() {
	local P4ROOT=$(p4_get_root)

	local SERVER_NAME=$_SERVER_NAME

	# If no --server_name was provided, then we set one
	if [[ "$SERVER_NAME" -eq "-1" || $SERVER_NAME = "" ]]; then
		# For some reason, p4 configure show serverid doesn't work, even thou it shows up when running p4 configure show
		SERVER_NAME=$(safe_command "cat $P4ROOT/server.id" true)
	fi
	if [[ "$SERVER_NAME" -eq "-1" || $SERVER_NAME = "" ]]; then
		force_exit_msg "No server name is set, please pass in --server_name to ensure that you know where your backup is stored"
	fi
	echo $SERVER_NAME
}

function check_returncode_with_msg() {
	local RETURN_CODE=$1
	local ERROR_MESSAGE="$2"

	if [[ "$RETURN_CODE" -ne 0 ]]; then
		force_exit_msg "$ERROR_MESSAGE"
	fi
}

# @returns 1 on yes and 0 on no
function ask_yes_no_question() {
	local QUESTION="$1"
	local ANSWER=""

	echo -e "$QUESTION ([y/n])"
	while [ true ]; do
		read ANSWER
		if [[ "${ANSWER,,}" == "y" || "${ANSWER,,}" == "yes" ]]; then
			return 1
		elif [[ "${ANSWER,,}" == "n" || "${ANSWER,,}" == "no" ]]; then
			return 0
		else
			echo -e "Please answer with y/n, yes/no\n"
		fi
	done
}

function show_var() {
	local VARNAME=$1

	echo -e "$VARNAME='${!VARNAME}'"
}

function from_func() {
	cut -d ' ' -f 2 <<< `caller 1`
}

function parse_md5_file_content() {
	local MD5_FILE_CONTENT="$1"

	echo -e $(sed -nE 's/^MD5 \(.+\) = (.+)$/\1/p' <<< "$MD5_FILE_CONTENT")

}

function require_param() {
	local VARNAME="$1"
	local PARAMETER_NAME="$2"

	if [[ "${!VARNAME}" == "-1" || "${!VARNAME}" == "" ]]; then
		force_exit_msg "$(from_func) failed: reqires $PARAMETER_NAME to be passed!\n$(callstack)"
	fi
}


function temporary_backup_bad_db() {
	local P4ROOT=$(p4_get_root)

	verbose_log "Making backup of db-files to /tmp/perforce_restore/..."
	run_as "mkdir /tmp/perforce_restore" "perforce" false
	if [[ $(ls /mnt/PerforceLive/root | grep db. | wc -l) -gt 0 ]]; then
		safe_command "mv $P4ROOT/db.* /tmp/perforce_restore/" true

		safe_command "chown -R perforce:perforce /tmp/perforce_restore/"
		safe_command "chmod -R 755 /tmp/perforce_restore/"
	else
		verbose_log "No db.* files to backup..."
	fi
}

function set_perforce_permissions() {
	local FILES="$1"; shift
	local OPTS="$1"

	safe_command "chown $OPTS perforce:perforce $FILES"
	safe_command "chmod $OPTS 700 $FILES"
}

function remove_bad_db_backup() {
	verbose_log "Removing /tmp/perforce_restore after restoring db"
	safe_command "rm -rf /tmp/perforce_restore"
}

function gcloud_setup() {
	verbose_log "Running gcloud_setup..."

	require_param "_GCLOUD_USER"			"--gcloud_user"
	require_param "_GCLOUD_PROJECT"		"--gcloud_project"
	require_param "_GCLOUD_BUCKET" 		"--gcloud_bucket"
	require_param "_GCLOUD_BACKUP_USER" 	"--gcloud_backup_user"
	require_param "_GCLOUD_BACKUP_ROLE" 	"--gcloud_backup_role"

	# Declare local variable that doesn't change the $?
	declare -I GCLOUD_OUTPUT

	gc_login "$_GCLOUD_USER"

	# Ensure that we are working on the correct project
	GCLOUD_OUTPUT=$(gc_safe_gcloud "config set project $_GCLOUD_PROJECT" true)

	if [[ "$GCLOUD_OUTPUT" == *"WARNING: You do not appear to have access to project [$_GCLOUD_PROJECT] or it does not exist."* ]]; then
		force_exit_msg "gcloud_setup failed: You don't have permission or the project $_GCLOUD_PROJECT doesn't exist: Error: \n'$GCLOUD_OUTPUT'"
	fi

	gc_create_bucket_if_not_exist "$_GCLOUD_BUCKET"
	gc_create_or_update_backup_role "$_GCLOUD_BACKUP_ROLE"
	gc_create_or_update_backup_user "$_GCLOUD_BACKUP_USER"

	if [[ ! -d /opt/perforce ]]; then
		verbose_log	"Creating /opt/perforce if it doesn't exist"
		safe_command "mkdir /opt/perforce/" true
	fi

	# Verify that the file is exists and is for the correct project...
	local KEY_IS_OUTDATED=false
	if [[ ! -f "$(gc_backup_account_cred_file)" ]]; then
		KEY_IS_OUTDATED=true
	else
		local PROJECT_ID=`jq -r '.project_id' $(gc_backup_account_cred_file)`
		if [[ "$PROJECT_ID" != "$_GCLOUD_PROJECT" ]]; then
			verbose_log "Key is for the wrong project... $PROJECT_ID"
			KEY_IS_OUTDATED=true
		fi
		local CLIENT_EMAIL=`jq -r '.client_email' $(gc_backup_account_cred_file)`
		if [[ "$CLIENT_EMAIL" != "$(gc_get_backup_account_mail)" ]]; then
			verbose_log "Key is for the wrong account... $CLIENT_EMAIL"
			KEY_IS_OUTDATED=true
		fi

		if $KEY_IS_OUTDATED; then
			verbose_log "Deleting old key as it's outdated"
			safe_command "rm -f $(gc_backup_account_cred_file)" true
		fi
	fi

	if $KEY_IS_OUTDATED; then
		verbose_log "Downloading credentials file for service-account"
		gc_safe_gcloud "iam service-accounts keys create $(gc_backup_account_cred_file) --iam-account=$(gc_get_backup_account_mail)" true
		set_perforce_permissions "$(gc_backup_account_cred_file)"
	else
		verbose_log "Skipping downloading of credentials as it's already downloaded"
	fi	

	if [[ "$_NO_REVOKE" -ne "0" ]]; then
		# Revoke our credentials so that they don't stay on the server by accident
		gc_safe_gcloud "auth revoke $_GCLOUD_USER"
	fi
}

function trim_checkpoints() {
	local P4ROOT=$(p4_get_root)
	local JOURNAL_DIR=$(p4_get_journal_dir)

	local CURRENT_TIME_SECONDS=$(date +%s)

	ls "$P4ROOT/$JOURNAL_DIR" | grep -E ".*\.ckp\.[0-9]*\.gz$" | sort -t . -k 3n | head -n -$_MAINTENENCE_CHECKPOINT_MIN_NUM | while read -r CHECKPOINT_FILE; do
		local NUM_DAYS_OLD=$(( (CURRENT_TIME_SECONDS - $(stat -c %Y "$P4ROOT/$JOURNAL_DIR/$CHECKPOINT_FILE")) / 86400 )) # 86400 seconds in a day
		if [ $NUM_DAYS_OLD -gt $_MAINTENENCE_CHECKPOINT_MAX_AGE_IN_DAYS ]; then
			verbose_log "Removing old checkpoint file $CHECKPOINT_FILE"
			safe_command "rm -f $P4ROOT/$JOURNAL_DIR/$CHECKPOINT_FILE"
			safe_command "rm -f $P4ROOT/$JOURNAL_DIR/$CHECKPOINT_FILE.md5"
		fi
	done
}

function wait_for_permission() {
	local COMMAND="$1"
	local DESCRIPTION="$2"

	local PERMISSION_PROPAGATION=1 # Success is 0
	local RETRIES=0
	while true; do
		if ! gcloud $COMMAND &> /dev/null; then
			if [[ "$RETRIES" -gt 42 ]]; then
				force_exit_msg "$DESCRIPTION hasn't propagated within 7 minutes... Aborting backup..."
			fi
			((RETRIES++))
			verbose_log "Waiting for ${DESCRIPTION,,} propagation. Waiting 10 seconds before retrying (Retry $RETRIES)..."
			sleep 10
		else
			break
		fi
	done
}

function wait_for_permission_propagation() {
	wait_for_permission "storage objects list gs://$_GCLOUD_BUCKET/* --limit=1" "Object permissions"
	wait_for_permission "storage buckets describe gs://$_GCLOUD_BUCKET" "Bucket permissions"
}

function nightly_backup() {
	# Reference: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup-procedure.html
	require_param "_GCLOUD_PROJECT" "--gcloud_project"
	require_param "_GCLOUD_BUCKET" "--gcloud_bucket"
	require_param "_GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "_P4_TICKET" "-t|--p4_ticket"

	local P4ROOT=$(p4_get_root)

	local JOURNAL_DIR=$(p4_get_journal_dir)
	local ARCHIVES_DIR=$(p4_get_archives_dir)
	
	# 1. Make checkpoint and ensure that it was successful
	verbose_log "Making checkpoint..."
		
	local CHECKPOINT_OUTPUT=$(p4d_run "-jc -z" true)

	# 2. Ensure the checkpointing was successful
	local JOURNAL_BACKUP_FILE=`sed -nE 's/^Checkpointing to (.+)...$/\1/p' <<< $CHECKPOINT_OUTPUT`
	local CHECKPOINT_REPORTED_MD5=$(parse_md5_file_content "$CHECKPOINT_OUTPUT")
	
	verbose_log "Validating journal file was correctly written to disk..."
	# Validate journal file
	p4d_run "-jv \"$P4ROOT/$JOURNAL_BACKUP_FILE\"" true false
	# 3. Confirm checkpoint was correctly written to disk with md5
	gzip -dk "$P4ROOT/$JOURNAL_BACKUP_FILE"

	local JOURNAL_BACKUP_FILE_WITHOUT_GZ=$P4ROOT/${JOURNAL_BACKUP_FILE%.gz}
	local MD5_FILE_CONTENT=$(parse_md5_file_content "`cat $JOURNAL_BACKUP_FILE_WITHOUT_GZ.md5`")
	if [[ "${MD5_FILE_CONTENT^^}" != "${CHECKPOINT_REPORTED_MD5^^}" ]]; then
		force_exit_msg "MD5 file has become corrupted during write! Aborting backup"
	fi

	verify_checkpoint "$JOURNAL_BACKUP_FILE_WITHOUT_GZ"

	# Remove the extracted file that we used to verify the md5 of
	safe_command "rm -f \"$JOURNAL_BACKUP_FILE_WITHOUT_GZ\""

	# 4. Trim down amount of checkpoints stored locally on the server
	trim_checkpoints
	
	# 5. Backup
	# Set correct project in google cloud
	verbose_log "Authenticating with google cloud storage..."
	gc_safe_gcloud "auth login $(gc_get_backup_account_mail) --cred-file=$(gc_backup_account_cred_file)" true
	gc_safe_gcloud "config set project $_GCLOUD_PROJECT"

	# If running this script right after you have setup the user and role, then we need to wait for the permission to propagate from IAM to STORAGE
	wait_for_permission_propagation

	local GS_BASE_PATH=$(gc_get_bucket_base_path)

	verbose_log "Sending journals and checkpoints to google cloud..."
	# 	checkpoint + md5, rotated journal file
	gc_safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "$P4ROOT/$JOURNAL_DIR" $GS_BASE_PATH/journals" true
	#	license file
	if [ -f $P4ROOT/license ]; then
		verbose_log "Sending license to google cloud..."
		gc_safe_gcloud "storage cp "$P4ROOT/license" $GS_BASE_PATH/license" true
	fi
	#	versioned files
	verbose_log "Sending content to google cloud..."
	gc_safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "$P4ROOT/$ARCHIVES_DIR" $GS_BASE_PATH/archives" true

	# 6. backup the server.id
	if [ -f $P4ROOT/server.id ]; then
		verbose_log "Sending server.id to google cloud..."
		gc_safe_gcloud "storage cp "$P4ROOT/server.id" $GS_BASE_PATH/server.id" true
	fi

	if [[ "$_NO_REVOKE" -ne "0" ]]; then
		# Revoke our credentials so that they don't stay on the server by accident
		gc_safe_gcloud "auth revoke $_GCLOUD_USER"
	fi

	verbose_log "Nightly backup succeeded"
}

function weekly_verification() {
	require_param "_P4_TICKET" "-t|--p4_ticket"

	# 1. Verify archive files
	p4_run "verify -q //..."
	# 2. Verify shelved files 
	p4_run "verify -q -S //..."

	verbose_log "Weekly verification succeeded"
}

# To delete the DB-files to test it, use the following command
# sudo find <P4ROOT> -type f -name db.* -exec rm {} \;
function restore_db() {
	force_exit_msg "restore_db not implemented yet"
	# This doesn't need to be implemented right now, as current usecase doesn't store the db on a different harddrive than the files
	## How to restore is specified here: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup.recovery.database_corruption.html
	## 1. Requires "Last checkpoint file"
	## 1a, Get it from disk
	## 1b, Get it from gcm
	## 2. md5 of last checkpoint
	## 3. Current journal file
#
	## Steps:
	## 1. Stop the p4d server
	#stop_p4d
	## 2. Rename (or move) the database (db.*) files on your system
	#temporary_backup_bad_db
	# SHOULD BE HERE SOMEWHERE IN THE IMPLEMENTATION
#
#
	## 3. Verify the integrity of your checkpoint using a command like the following:
	## 4. Restore most recent journal file
#
	## Remember to do: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup-recovery-ensuring-integrity.html
	#remove_bad_db_backup
}


function run_as() {
	local COMMAND="$1"; shift
	local USER="$1"; shift
	local PRINT_RESULT=${1:-false}

	local USER_SWITCH_COMMAND=""
	if [[ "$(whoami)" != "$USER" ]]; then
		USER_SWITCH_COMMAND="sudo -u $USER"
	fi

	# Declare local variable that doesn't change the $?
	declare -I COMMAND_OUTPUT
	COMMAND_OUTPUT=$(eval "$USER_SWITCH_COMMAND $COMMAND 2>&1")
	local RESULT=$?
	if [[ $PRINT_RESULT = true ]]; then
		echo -e "$COMMAND_OUTPUT"
	fi

	return "$RESULT"
}

function verify_checkpoint() {
	local CHECKPOINT_FILE=$(realpath "$1")

	local PARSE_MD5_SED_CMD='s/^MD5 \(.+\) = (.+)$/\1/p'

	local MD5_FILE_CONTENT=$(parse_md5_file_content "`cat $CHECKPOINT_FILE.md5`")
	local MD5_OF_CHECKPOINT=`md5sum $CHECKPOINT_FILE | awk '{print $1}'`

	if [[ "${MD5_OF_CHECKPOINT^^}" != "${MD5_FILE_CONTENT^^}" ]]; then
		force_exit_msg "md5 of $CHECKPOINT_FILE mismatches with content of $CHECKPOINT_FILE.md5. Aborting!"
	fi
}

function fetch_license_and_server_id() {
	verbose_log "Fetching license and server id..."
	local FETCH_LICENSE=${1:-true}

	local FILES_TO_FETCH=""
	if gc_file_exists "$(gc_get_bucket_base_path)/server.id" -eq 0; then
		FILES_TO_FETCH="$(gc_get_bucket_base_path)/server.id"
	fi

	if $FETCH_LICENSE; then
		if gc_file_exists "$(gc_get_bucket_base_path)/license" -eq 0; then
			FILES_TO_FETCH="$FILES_TO_FETCH $(gc_get_bucket_base_path)/license"
		fi
	fi

	# Do we have any files to fetch, then we fetch them
	if [[ "${#FILES_TO_FETCH}" -gt 0 ]]; then
		local GCLOUD_OUTPUT=$(gc_safe_gcloud "storage cp $FILES_TO_FETCH $(p4_get_root)" true)
		local FILES=$(echo -e "$GCLOUD_OUTPUT" | grep -Po "^Copying gs://(.*) to file://\K(.*)$" | tr '\n' ' ')
		set_perforce_permissions "$FILES"
	else
		verbose_log "Neither license nor server.id to fetch"
	fi
}

function fetch_checkpoint_and_md5() {
	verbose_log "Fetching latest checkpoint and md5..."
	local CHECKPOINT_FILE_VAR="$1"

	# Declare local variable that doesn't change the $?
	declare -I GCLOUD_RESULT
	local BASE_PATH=$(gc_get_bucket_base_path)
	GCLOUD_RESULT=$(gc_safe_gcloud "storage ls $BASE_PATH/journals/" true)
	
	local LATEST_CHECKPOINT=$(echo -e "$GCLOUD_RESULT" | grep -E "^.*\.ckp\.(\d*).*\.gz$" | sort -t . -k 3n | tail -1)
	local LATEST_MD5=$(echo -e "${LATEST_CHECKPOINT%gz}md5")

	local P4ROOT="$(p4_get_root)"
	local P4JOURNAL_DIR="$P4ROOT/$(p4_get_journal_dir)"
	GCLOUD_RESULT=$(gc_safe_gcloud "storage cp $LATEST_CHECKPOINT $LATEST_MD5 $P4JOURNAL_DIR" true)
	
	local CHECKPOINT_FILE=$(echo -e "$GCLOUD_RESULT" | grep -Eo "$P4JOURNAL_DIR/(\w+)\.(\w+)\.[0-9]+\.gz$")
	local MD5_FILE=$(echo -e "$GCLOUD_RESULT" | grep -Eo "$P4JOURNAL_DIR/(\w+)\.(\w+)\.[0-9]+\.md5$")

	safe_command "gzip -df $CHECKPOINT_FILE"
	CHECKPOINT_FILE=`realpath "${CHECKPOINT_FILE%.gz}"`
		
	verify_checkpoint "$CHECKPOINT_FILE"

	# Set the variables passed into the function of the parent scope
	eval "$CHECKPOINT_FILE_VAR=$CHECKPOINT_FILE"

	set_perforce_permissions "$CHECKPOINT_FILE $CHECKPOINT_FILE.md5"
}

function fetch_versioned_files() {
	local GS_BASE_PATH=$(gc_get_bucket_base_path)
	local P4ROOT=$(p4_get_root)
	local ARCHIVES_DIR=$(p4_get_archives_dir)

	gc_safe_gcloud "storage rsync -r $GS_BASE_PATH/archives $P4ROOT/$ARCHIVES_DIR" true
	# Permissions might have changed after downloading the files
	set_perforce_permissions "$P4ROOT/$ARCHIVES_DIR" "-R"
}

function restore_db_and_files() {
	# How to restore is specified here: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup.recovery.damage.html
	require_param "_GCLOUD_PROJECT" "--gcloud_project"

	# Require root, as we will install packages with apt
	if is_root -eq "0" ; then
		force_exit_msg "Require root to run restore_db_and_files"
	fi

	verbose_log "Authenticating with google cloud storage..."
	gc_safe_gcloud "auth login $(gc_get_backup_account_mail) --cred-file=$(gc_backup_account_cred_file)" true
	gc_safe_gcloud "config set project $_GCLOUD_PROJECT"

	# Steps:
	# 1. RECOVER DATABASE
	# 1.1. Stop the p4d server
	verbose_log "Stopping the p4d service..."
	p4dctl_run "stop"
	# 1.2. Rename (or move) the corrupt database (db.*) files
	temporary_backup_bad_db
	# 1.3.1 Restore checkpoint and md5
	local CHECKPOINT_FILE_REF
	fetch_checkpoint_and_md5 CHECKPOINT_FILE_REF
	# 1.3.2 Get the license and server id
	fetch_license_and_server_id "$_FETCH_LICENSE"
	# 1.4. Invoke p4d with the -jr (journal-restore) flag, specifying only your most recent checkpoint as the perforce user
	p4d_run "$_P4_CASE -jr $CHECKPOINT_FILE_REF" true
	set_perforce_permissions "$(p4_get_root)" "-R"
	# 2. Recover versioned files
	fetch_versioned_files
	# 3. Start system again
	p4dctl_run "start"

	# 4. Check your system
	# 4.1 Check lastCheckpointAction when it was completed 
	LAST_CHECKPOINT_ACTION=$(p4_run "counter lastCheckpointAction" false)
	if ask_yes_no_question "'p4 counter lastCheckpointAction' gave output:\n'$LAST_CHECKPOINT_ACTION'\n after database restore, this is this date and time of last checkpoint, does this look resonable?" -eq "0"; then
		force_exit_msg "Restore was unsuccessful =/... Please do it manually according to: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup.recovery.damage.html"
	fi

	# 4.2 Verify all files on the depot and all shelved files
	verbose_log "Verifying files to ensure that the backup was successful..."
	p4_run "verify -q //..."
	p4_run "verify -q -S //..."

	# 5. If everything was successful, then we can delete the corrupted db.* files
	remove_bad_db_backup

	verbose_log "Restoration of db and files complete!"
}

function disable_default_maintenance() {
	verbose_log "Disabling default maintenance..."

	ls /etc/perforce/p4dctl.conf.d/ | grep -E ".*\.conf$" | while read -r FILE; do
		safe_command "sed -i 's/^\s*MAINTENANCE\s*=\s*true$/        MAINTENANCE =\tfalse/' /etc/perforce/p4dctl.conf.d/$FILE"
	done

	verbose_log "Restarting p4dctl..."
	p4dctl_run "restart"
}

function setup() {
	require_param "_MAIL_SENDER" "--mail_sender"
	require_param "_MAIL_TOKEN" "--mail_token"

	require_param "_GCLOUD_PROJECT" "--gcloud_project"
	require_param "_GCLOUD_BUCKET" "--gcloud_bucket"
	require_param "_GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "_P4_TICKET" "-t|--p4_ticket"

	# Require root, as we will install packages with apt
	if is_root -eq "0" ; then
		force_exit_msg "Require root to run setup"
	fi

	if [[ "$_NOTIFICATION_RECIPIENTS" == "-1" ]]; then
		if ask_yes_no_question "No mail notification recepients specified, continue anyway?" -eq 0; then
			force_exit_msg "Quitting for user to specify mail recepients"
		fi
	fi

	# Required for us to download signing keys for google cloud
	apt-get install apt-transport-https ca-certificates gnupg curl -y

	# If run again, delete old cloud key so we can get the new one
	if [[ -f "/usr/share/keyrings/cloud.google.gpg" ]]; then
		rm -f /usr/share/keyrings/cloud.google.gpg
	fi
	curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
	# If run again, delete old repository path
	if [[ -f "/etc/apt/sources.list.d/google-cloud-sdk.list" ]]; then
		rm -f /etc/apt/sources.list.d/google-cloud-sdk.list
	fi
	# Add google cloud repo
	echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
	# Install google cloud
	apt-get update && apt-get install google-cloud-cli jq -y

	# AuthPass is setup here: https://myaccount.google.com/u/1/apppasswords
	# Install ssmtp for sending mail through gmail
	apt install ssmtp -y
	echo "mailhub=smtp.gmail.com:587
useSTARTTLS=YES
AuthUser=$_MAIL_SENDER
AuthPass=$_MAIL_TOKEN
FromLineOverride=YES" > /etc/ssmtp/ssmtp.conf


	# Ensure the correct permissions for ssmtp files
	chown root:mail /etc/ssmtp/ssmtp.conf
	# This file contains a mail token, so only allow root to read it
	chmod 640 /etc/ssmtp/ssmtp.conf
	# Add the perforce user to the mail group so that it can send mail
	usermod -a -G mail perforce

	# Install the script so that cron can access it
	local SCRIPT_FILENAME=$(realpath "$0")
	local INSTALLED_PATH=/usr/sbin/$(basename "$0")

	safe_command "cp $SCRIPT_FILENAME $INSTALLED_PATH"
	safe_command "chmod 774 $INSTALLED_PATH"
	safe_command "chown perforce:perforce $INSTALLED_PATH"

	# Ensure that there is a /opt/perforce/backup directory with correct permissions
	if [ ! -d /opt/perforce/backup ]; then
		mkdir /opt/perforce/backup
		set_perforce_permissions  "/opt/perforce/backup" "-R"
	fi

	local MAINTENENCE_USER="perforce"

	# For explaination on crontab, see https://crontab.guru/#02_1_*_*_1-5,0
	local NIGHTLY_MAINTENENCE_TIME="2 1 * * 1-5,0"
	local NIGHTLY_MAINTENENCE_COMMAND="$INSTALLED_PATH --nightly"
	
	# For explaination on crontab, see https://crontab.guru/#2_1_*_*_6
	local WEEKLY_MAINTENENCE_TIME="2 1 * * 6"
	local WEEKLY_MAINTENENCE_COMMAND="$INSTALLED_PATH --nightly --weekly"

	# MAILTO="" is to disable mail sending, as we are using ssmtp in the script to send mail
	echo 'MAILTO=""' > "/etc/cron.d/perforce_maintenance"
	echo "$NIGHTLY_MAINTENENCE_TIME $MAINTENENCE_USER $NIGHTLY_MAINTENENCE_COMMAND" >> "/etc/cron.d/perforce_maintenance"
	echo "$WEEKLY_MAINTENENCE_TIME $MAINTENENCE_USER $WEEKLY_MAINTENENCE_COMMAND" >> "/etc/cron.d/perforce_maintenance"

	safe_command "chmod 640 /etc/cron.d/perforce_maintenance"

	disable_default_maintenance

	verbose_log "Setup is complete"
}

function read_config_file() {
	# Read the config file

	if [[ ! -f $(get_config_file) ]]; then
		# If the config doesn't exist, then we create it with the values that has been passed in (or default values)
		update_config_file
		set_perforce_permissions "$(get_config_file)"
	fi

	# Read the config file
	_GCLOUD_PROJECT=`jq -r			'.project_id' $(get_config_file)`
	_GCLOUD_BUCKET=`jq -r			'.bucket' $(get_config_file)`
	_GCLOUD_BACKUP_USER=`jq -r		'.backup_user' $(get_config_file)`
	_GCLOUD_BACKUP_ROLE=`jq -r		'.backup_role' $(get_config_file)`
	_MAIL_SENDER=`jq -r				'.mail_sender' $(get_config_file)`
	_MAIL_TOKEN=`jq -r				'.mail_token' $(get_config_file)`
	_NOTIFICATION_RECIPIENTS=`jq -r	'.notification_recipients' $(get_config_file)`
	_P4_TICKET=`jq -r				'.p4_ticket' $(get_config_file)`
}

function update_config_file() {
	run_as "echo -e \"{
	\\\"project_id\\\": \\\"$_GCLOUD_PROJECT\\\",
	\\\"bucket\\\": \\\"$_GCLOUD_BUCKET\\\",
	\\\"backup_user\\\": \\\"$_GCLOUD_BACKUP_USER\\\",
	\\\"backup_role\\\": \\\"$_GCLOUD_BACKUP_ROLE\\\",
	\\\"mail_sender\\\": \\\"$_MAIL_SENDER\\\",
	\\\"mail_token\\\": \\\"$_MAIL_TOKEN\\\",
	\\\"notification_recipients\\\": \\\"$_NOTIFICATION_RECIPIENTS\\\",
	\\\"p4_ticket\\\": \\\"$_P4_TICKET\\\"
}\" > $(get_config_file)" "perforce"
	set_perforce_permissions "$(get_config_file)"
}

function interactive_update_glcoud_settings() {
	local BAD_USER=false
	while true; do
		clear
		if $BAD_USER; then
			echo "Failed to login with user [$GCLOUD_USER], try another user..."
		fi

		local GCLOUD_OUTPUT=$(gc_safe_gcloud "auth list --format=json" true)
		_GCLOUD_USER=$(echo -e "$GCLOUD_OUTPUT" | jq -r '.[] | select(.status=="ACTIVE") | .account')

		read -p "Enter user to setup the google cloud intergration with [$_GCLOUD_USER] : " GCLOUD_USER
		GCLOUD_USER=${GCLOUD_USER:-$_GCLOUD_USER}

		if gc_login "$GCLOUD_USER" -eq 0; then
			_GCLOUD_USER=$GCLOUD_USER
			break
		fi
		BAD_USER=true
	done
	BAD_USER=false

	local BAD_PROJECT=false
	while true; do
		clear
		if $BAD_PROJECT; then
			echo -e "You don't have permission or the project [$GCLOUD_PROJECT] doesn't exist: Error: \n'$GCLOUD_OUTPUT'"
		fi
		echo "Administrator user [$_GCLOUD_USER]"

		read -p "Enter Project id [$_GCLOUD_PROJECT]: " GCLOUD_PROJECT
		GCLOUD_PROJECT=${GCLOUD_PROJECT:-$_GCLOUD_PROJECT}

		# Ensure that we have permission to the specified project
		GCLOUD_OUTPUT=$(gc_safe_gcloud "config set project $GCLOUD_PROJECT" true)

		if [[ "$GCLOUD_OUTPUT" == *"WARNING: You do not appear to have access to project [$GCLOUD_PROJECT] or it does not exist."* ]]; then
			BAD_PROJECT=true
		else
			_GCLOUD_PROJECT=$GCLOUD_PROJECT
			break
		fi
	done
	update_config_file

	clear
	echo "Administrator user [$_GCLOUD_USER]"
	echo "Project id [$_GCLOUD_PROJECT]"

	read -p "Enter Bucket id [$_GCLOUD_BUCKET]: " GCLOUD_BUCKET
	GCLOUD_BUCKET=${GCLOUD_BUCKET:-$_GCLOUD_BUCKET}

	gc_create_bucket_if_not_exist "$GCLOUD_BUCKET"
	_GCLOUD_BUCKET=$GCLOUD_BUCKET
	update_config_file

	clear
	echo "Administrator user [$_GCLOUD_USER]"
	echo "Project id [$_GCLOUD_PROJECT]"
	echo "Bucket id [$_GCLOUD_BUCKET]"

	read -p "Enter Backup role [$_GCLOUD_BACKUP_ROLE]: " GCLOUD_BACKUP_ROLE
	GCLOUD_BACKUP_ROLE=${GCLOUD_BACKUP_ROLE:-$_GCLOUD_BACKUP_ROLE}
	gc_create_or_update_backup_role "$GCLOUD_BACKUP_ROLE"
	_GCLOUD_BACKUP_ROLE=$GCLOUD_BACKUP_ROLE
	update_config_file

	clear
	echo "Administrator user [$_GCLOUD_USER]"
	echo "Project id [$_GCLOUD_PROJECT]"
	echo "Bucket name [$_GCLOUD_BUCKET]"
	echo "Backup role [$_GCLOUD_BACKUP_ROLE]"

	read -p "Enter Backup user [$_GCLOUD_BACKUP_USER] (not full mail): " GCLOUD_BACKUP_USER
	# Validate input, åäö will cause the script to fail...
	GCLOUD_BACKUP_USER=${GCLOUD_BACKUP_USER:-$_GCLOUD_BACKUP_USER}
	gc_create_or_update_backup_user "$GCLOUD_BACKUP_USER"
	_GCLOUD_BACKUP_USER=$GCLOUD_BACKUP_USER
	update_config_file

	clear
	echo "Administrator user [$_GCLOUD_USER]"
	echo "Project id [$_GCLOUD_PROJECT]"
	echo "Bucket name [$_GCLOUD_BUCKET]"
	echo "Backup role [$_GCLOUD_BACKUP_ROLE]"
	echo "Backup user [$_GCLOUD_BACKUP_USER]"

	ask_yes_no_question "Do you want to complete the setup with these settings?"
	# If user made some bad changes, then he/she will be asked to try again
	if [[ $? -eq 0 ]]; then
		interactive_update_glcoud_settings
		return
	fi

	gcloud_setup

	echo "Setup of cloud provider complete"
	sleep 2
}

function interactive_setup_cloud_provider() {
	local BAD_OPTION=false
	while true; do
		clear
		if [[ $BAD_OPTION == true ]]; then
			echo "Invalid option... Try again"
		fi

		echo "Select cloud provider:"
		echo "1. Google Cloud"
		echo "2. Amazon Web Services (uninplemented)"
		echo "3. Microsoft Azure (uninplemented)"
		echo "4. Back"

		read OPTION
		case $OPTION in
			1) BAD_OPTION=false; interactive_update_glcoud_settings ;;
			2) BAD_OPTION=true ;;
			3) BAD_OPTION=true ;;
			4) return ;;
			*) BAD_OPTION=true ;;
		esac
	done
}

function interactive_configure_server() {
	if is_root -eq 0; then
		return
	fi

	clear

	echo -e "Mail sender is the mail address that will send notifications\n"
	read -p "Enter mail sender: [$_MAIL_SENDER]: " MAIL_SENDER
	MAIL_SENDER=${MAIL_SENDER:-$_MAIL_SENDER}
	# @TODO: Add verification that the token and mail is correct
	_MAIL_SENDER=$MAIL_SENDER
	update_config_file

	clear
	echo -e "Mail token is the token that's used by gmail to authenticate the user\n"
	echo -e "Mail sender: [$_MAIL_SENDER]"
	read -p "Enter Mail sender token [$_MAIL_TOKEN]: " MAIL_TOKEN
	MAIL_TOKEN=${MAIL_TOKEN:-$_MAIL_TOKEN}
	_MAIL_TOKEN=$MAIL_TOKEN
	# @TODO: Add verification that the token and mail is correct
	update_config_file

	clear
	echo -e "P4 ticket is a ticket that's used to authenticate the SuperUser account that's used to make the backups. Preferably not a expiring ticket\n"
	echo -e "Mail sender: [$_MAIL_SENDER]"
	echo -e "Mail sender token [$_MAIL_TOKEN]"
	read -p "Enter P4 Ticket [$_P4_TICKET]: " P4_TICKET
	P4_TICKET=${P4_TICKET:-$_P4_TICKET}
	# @todo: Verify the P4_TICKET
	_P4_TICKET=$P4_TICKET
	update_config_file

	clear
	echo -e "Mail notification recepients is a comma separated list of email adresses that want to receive mail when something goes wrong\n"
	echo -e "Mail sender: [$_MAIL_SENDER]"
	echo -e "Mail sender token [$_MAIL_TOKEN]"
	echo -e "P4 Ticket [$_P4_TICKET]"
	read -p "Enter Mail notification recepients [$_NOTIFICATION_RECIPIENTS]: " NOTIFICATION_RECIPIENTS
	NOTIFICATION_RECIPIENTS=${NOTIFICATION_RECIPIENTS:-$_NOTIFICATION_RECIPIENTS}
	# @todo: Verify the NOTIFICATION_RECIPIENTS
	_NOTIFICATION_RECIPIENTS=$NOTIFICATION_RECIPIENTS
	update_config_file

	setup
}

function interactive(){
	local BAD_OPTION=false

	local IS_ROOT=true
	local IS_ROOT_MSG=""
	if is_root -eq 0; then
		IS_ROOT_MSG="(require script to be run as root)"
		IS_ROOT=false
	fi

	local OPTION=0
	while true; do
		clear

		if $BAD_OPTION; then
			if [ $OPTION -eq 2 ]; then
				echo "Require root to run setup. Restart script with root access"
			else
				echo "Invalid option. Try again..."
			fi
		fi

		echo "Select option:"
		echo "1. Setup cloud provider"
		echo "2. Configure server $IS_ROOT_MSG"
		echo "3. Restore perforce backup (uninplemented)"
		echo "4. Make backup (uninplemented)"
		echo "5. Verify integrity (uninplemented)"
		echo "6. Exit"		

		read OPTION
		case $OPTION in
			1) BAD_OPTION=false; interactive_setup_cloud_provider; ;;
			2) BAD_OPTION=$(! $IS_ROOT && echo "true" || echo "false"); interactive_configure_server ;;
			3) BAD_OPTION=true ;; #restore_db ;;
			4) BAD_OPTION=true ;; #nightly_backup ;;
			5) BAD_OPTION=true ;; #weekly_verification ;;
			6) exit 0 ;;
			*) BAD_OPTION=true ;;
		esac
	done
}

## Here the script starts
read_config_file


if [[ "$_INTERACTIVE" -eq 1 ]]; then
	interactive
fi

if [[ "$_SETUP" -eq 1 ]]; then
	setup
fi

if [[ "$_GCLOUD_SETUP" -eq 1 ]]; then
	gcloud_setup
fi

# Different restoremodes to run
case "$_RESTORE" in
	db) 
		restore_db ;;
	db_and_files) 
		restore_db_and_files ;;
esac

if [[ "$_WEEKLY" -eq 1 ]]; then
	weekly_verification
fi

if [[ "$_NIGHTLY" -eq 1 ]]; then
	nightly_backup
fi