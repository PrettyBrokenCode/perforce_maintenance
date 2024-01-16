#!/bin/bash

# ability to use echoerr "Error message" to print to stderr instead of stdout
function echoerr() { echo -e "$@" 1>&2; }

TEMP=$(getopt -o v,m:,n,w,t:,s,u:,r: -l no_revoke,verbose,p4_user:,mail:,gcloud_backup_role:,gcloud_user:,gcloud_setup,gcloud_bucket:,gcloud_project:,gcloud_backup_user:,nightly,weekly,p4_ticket:,setup,mail_sender:,mail_token:,server_name:,restore:,p4_root:,p4_journal:,p4_windows_case,p4_archive_dir:,no_fetch_license -- "$@")
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

_FETCH_LICENSE=true
_VERBOSE=0
_NO_REVOKE=0

_NIGHTLY=0
_WEEKLY=0
_SETUP=0
_RESTORE=0

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

if [[ "$_NIGHTLY" -eq 0 && "$_WEEKLY" -eq 0 && "$_GCLOUD_SETUP" -eq 0 && "$_SETUP" -eq 0 && "$_RESTORE" -ne 0 ]]; then
	echoerr "Either nightly, weekly, setup, restore or weekly_setup needs to be set for the backupscript to run"
	echoerr "EXITING!"
	exit -1
fi

# @TODO: Move all variables that's export into the call of perforce instead of using environment variables and make helper function p4 and safe_p4
export P4PASSWD="$_P4_TICKET"
export P4USER=$_P4_USER

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
	local i=1 max_depth=-1 line file func skip_first
	# First parameter determines how many layers of callers we want to skip at start
	if [[ "$#" -ge 1 ]]; then
		i="$1"
	fi
	if [[ "$#" -ge 2 ]]; then
		max_depth="$2"
	fi

	while read -r line func file < <(caller $i); do
		echo "[$i] $file:$line $func(): $(sed -n ${line}p $file)"

		if [[ "$max_depth" -ne "-1" && "$i" -ge "$max_depth" ]]; then
			break
		fi

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

	echo -e "Sending notification to: '$_NOTIFICATION_RECIPIENTS'"

	# Verify that we have specified the notification recipient
	if [[ "$_NOTIFICATION_RECIPIENTS" != -1 ]]; then
		echo -e "From: Perforce Server\nSubject: Perforce server backup failed\n\n$MESSAGE" | ssmtp $_NOTIFICATION_RECIPIENTS
	else
		verbose_log "No notification recipient specified, no mail sent"
	fi
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

function safe_gcloud() {
	local COMMAND="$1"
	shift
	local PRINT_RESULT=${1:-false}

	safe_command "gcloud $COMMAND -q" "$PRINT_RESULT"
}

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

function get_p4_port() {
	local ETH_ADAPTER=eth0
	local IP_ADDR=`ip a s $ETH_ADAPTER | grep -E -o 'inet [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d' ' -f2`
	# @TODO: Make this configurable
	echo "$IP_ADDR:1666"
}

# Helper function to get p4 config values, takes 1-2 parameters
# @param 1 The variable we want to pass to p4 configure show
# @param 2 if false, we are not operating in strict mode, and will not terminate the
#       application if the config variable doesn't exist
# @param 3 if false, then we don't print the output of p4 configure show. Only valid if strict is false
function get_p4config_value() {
	local CONFIG_VAR="$1"; shift
	local STRICT=${1:-true}; shift
	local PRINT_ERROR=${1:-true}
	
	# Get config value
	local CONFIG_OUTPUT=$(run_p4 "configure show $CONFIG_VAR" "$STRICT")
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
	$func_name "$EXECUTABLE -p $(get_p4_port) -u $_P4_USER $COMMAND $CAPTURE_STRING" "perforce" "$PRINT_RESULT"
}

function run_p4() {
	require_param "_P4_TICKET" "--p4_ticket"

	local COMMAND="$1"; shift
	local SAFE=${1:-true}; shift
	local PRINT_RESULT=${1:-true}

	_p4_internal "p4" "-P $_P4_TICKET $COMMAND" "$SAFE" "$PRINT_RESULT" "$CAPTURE_ALL"
}

function run_p4d() {
	local COMMAND="$1"; shift
	local SAFE=${1:-true}; shift
	local PRINT_RESULT=${1:-true}

	local P4_ROOT=$(get_p4_root)

	_p4_internal "p4d" "-r \"$P4_ROOT\" $COMMAND" "$SAFE" "$PRINT_RESULT" "$CAPTURE_ALL"
}

function run_p4dctl() {
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

function get_p4_root() {
	# Declare local variable that doesn't change the $?
	declare -I P4ROOT
	P4ROOT=$(get_p4config_value P4ROOT false false)
	if [[ $? != 0 ]]; then	
		require_param "_P4_ROOT" "--p4_root"
		P4ROOT=$_P4_ROOT
	fi
	echo $P4ROOT
}

function get_p4_archives_dir() {
	declare -I ARCHIVES_DIR
	ARCHIVES_DIR=$(get_p4config_value server.depot.root false false)
	if [[ $? -ne 0 ]]; then
		require_param "_P4_ARCHIVES_DIR" "--p4_archive_dir"
		ARCHIVES_DIR="$_P4_ARCHIVES_DIR"
	fi
	echo -e "$ARCHIVES_DIR"
}


function check_returncode_with_msg() {
	local RETURN_CODE=$1
	local ERROR_MESSAGE="$2"

	if [[ "$RETURN_CODE" -ne 0 ]]; then
		force_exit_msg "$ERROR_MESSAGE"
	fi
}

function get_p4_journal_dir() {
	declare -I JOURNAL_FILE
	JOURNAL_FILE=$(get_p4config_value P4JOURNAL false false)
	if [[ $? -ne 0 ]]; then
		require_param "_P4_JOURNAL" "--p4_journal"
		JOURNAL_FILE=$_P4_JOURNAL
	fi

	echo -e "${JOURNAL_FILE%/*}"
}

function get_backup_account_mail() {
	require_param "_GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "_GCLOUD_PROJECT" "--gcloud_project"

	echo "$_GCLOUD_BACKUP_USER@$_GCLOUD_PROJECT.iam.gserviceaccount.com"
}

function get_gs_bucket_base_path() {
	require_param "_GCLOUD_BUCKET" "--gcloud_bucket"

	local SERVER_NAME=$(get_server_name)

	echo -e "gs://$_GCLOUD_BUCKET/$SERVER_NAME"
}

function get_backup_role_absolute_path() {
	require_param "_GCLOUD_PROJECT" "--gcloud_project"
	require_param "_GCLOUD_BACKUP_ROLE" "--gcloud_backup_role"

	echo "projects/$_GCLOUD_PROJECT/roles/$_GCLOUD_BACKUP_ROLE"
}

function gs_backup_account_cred_file() {
	echo "/opt/perforce/backup/gs_backup_user_key.json"
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

	echo -e $(sed -nE 's/^MD5 \(.+\) = (.+)$/\1/p' <<< $MD5_FILE_CONTENT)

}

function get_server_name() {
	local P4ROOT=$(get_p4_root)

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

function require_param() {
	local VARNAME="$1"
	local PARAMETER_NAME="$2"

	if [[ "${!VARNAME}" == "-1" || "${!VARNAME}" == "" ]]; then
		force_exit_msg "$(from_func) failed: reqires $PARAMETER_NAME to be passed!\n$(callstack)"
	fi
}


function temporary_backup_bad_db() {
	local P4ROOT=$(get_p4_root)

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
	verbose_log "Running SETUP"

	require_param "_GCLOUD_USER"			"--gcloud_user"
	require_param "_GCLOUD_PROJECT"		"--gcloud_project"
	require_param "_GCLOUD_BUCKET" 		"--gcloud_bucket"
	require_param "_GCLOUD_BACKUP_USER" 	"--gcloud_backup_user"
	require_param "_GCLOUD_BACKUP_ROLE" 	"--gcloud_backup_role"

	# Declare local variable that doesn't change the $?
	declare -I GCLOUD_OUTPUT

	# Check if the user is already logged in
	GCLOUD_OUTPUT=$(safe_gcloud "auth list --filter-account=$_GCLOUD_USER --format=json" true)

	# Need to login, so run interactive prompt (don't use safe_gcloud or safe_command)
	if  [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq "0" ]]; then
		gcloud auth login $_GCLOUD_USER
		check_returncode_with_msg "$?" "gcloud_setup failed: Failed to login"
	else
		verbose_log "Setting account $_GCLOUD_USER"
		# Set the active account
		safe_gcloud "config set account $_GCLOUD_USER" true
	fi

	# Ensure that we are working on the correct project
	GCLOUD_OUTPUT=$(safe_gcloud "config set project $_GCLOUD_PROJECT" true)

	if [[ "$GCLOUD_OUTPUT" == *"WARNING: You do not appear to have access to project [$_GCLOUD_PROJECT] or it does not exist."* ]]; then
		force_exit_msg "gcloud_setup failed: You don't have permission or the project $_GCLOUD_PROJECT doesn't exist: Error: \n'$GCLOUD_OUTPUT'"
	fi

	# check if the bucket exists
	GCLOUD_OUTPUT=$(safe_gcloud "storage buckets list --filter=$_GCLOUD_BUCKET --format=json" true)

	# Bucket doesn't exist, create it
	if  [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		verbose_log "Creating bucket"
		safe_gcloud "storage buckets create gs://$_GCLOUD_BUCKET/ \
		--uniform-bucket-level-access \
		--default-storage-class=Standard \
		--location=EUROPE-NORTH1 \
		--pap \
		2>&1" true
	else
		verbose_log "Skipping creating bucket, as it already exists"
	fi

	# The required permission of the backup role
	local REQUIRED_PERMISSIONS="storage.objects.list,storage.objects.create,storage.objects.delete,storage.objects.get"

	# Check if the role exists
	gcloud iam roles describe $_GCLOUD_BACKUP_ROLE --project=$_GCLOUD_PROJECT > /dev/null
	
	# If the backup role doesn't exist, create it
	if [[ "$?" -eq "1" ]]; then
		# @TODO: Verify that permissions are set correctly
		verbose_log "Creating backup role with correct permissions"
		safe_gcloud "iam roles create $_GCLOUD_BACKUP_ROLE --project=$_GCLOUD_PROJECT --permissions=$REQUIRED_PERMISSIONS" true
	else
		verbose_log "Updating backup role with correct permissions"
		safe_gcloud "iam roles update $_GCLOUD_BACKUP_ROLE --project=$_GCLOUD_PROJECT --permissions=$REQUIRED_PERMISSIONS" true
	fi

	GCLOUD_OUTPUT=`gcloud iam service-accounts list --format=json --filter=$(get_backup_account_mail) 2>&1`

	if [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		# User doesn't exist, create it
		safe_gcloud "iam service-accounts create $_GCLOUD_BACKUP_USER --display-name=\"Perforce backup user\"" true
	else
		verbose_log	"Skipping creating service account as it already exists"
	fi

	# Get the roles of the service account to verify that the service account has the correct role
	GCLOUD_OUTPUT=$(safe_gcloud "projects get-iam-policy $_GCLOUD_PROJECT --flatten='bindings[].members' \
		--format='table(bindings.role)' \
		--filter='bindings.members:serviceAccount:$(get_backup_account_mail) AND \
			bindings.role=$(get_backup_role_absolute_path)' --format=json" true)

	if [[ $(echo -e "$GCLOUD_OUTPUT" | jq length) -eq 0 ]]; then
		# Add the role to the service account
		verbose_log "Adding the role $(get_backup_role_absolute_path) to backup user $(get_backup_account_mail)"
		safe_gcloud "projects add-iam-policy-binding $_GCLOUD_PROJECT \
			--role=$(get_backup_role_absolute_path) \
			--member=serviceAccount:$(get_backup_account_mail)" true
	else
		verbose_log "Skipping adding role to backup user, as it already has it"
	fi

	if [[ ! -d /opt/perforce ]]; then
		verbose_log	"Creating /opt/perforce if it doesn't exist"
		safe_command "mkdir /opt/perforce/" true
	fi

	# @TODO: Check if the key if for the current backup user, and if not, delete old key and download a new key
	if [[ ! -f "$(gs_backup_account_cred_file)" ]]; then
		verbose_log "Downloading credentials file for service-account"
		safe_gcloud "iam service-accounts keys create $(gs_backup_account_cred_file) --iam-account=$(get_backup_account_mail)" true
		set_perforce_permissions "$(gs_backup_account_cred_file)"
	else
		verbose_log "Skipping downloading of credentials as it's already downloaded"
	fi

	if [[ "$_NO_REVOKE" -ne "0" ]]; then
		# Revoke our credentials so that they don't stay on the server by accident
		safe_gcloud "auth revoke $_GCLOUD_USER"
	fi

	force_exit
}

function nightly_backup() {
	# Reference: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup-procedure.html
	require_param "_GCLOUD_PROJECT" "--gcloud_project"
	require_param "_GCLOUD_BUCKET" "--gcloud_bucket"
	require_param "_GCLOUD_BACKUP_USER" "--gcloud_backup_user"
	require_param "_P4_TICKET" "-t|--p4_ticket"


	local P4ROOT=$(get_p4config_value P4ROOT)

	local JOURNAL_DIR=$(get_p4_journal_dir)
	local ARCHIVES_DIR=$(get_p4_archives_dir)
	
	# 1. Make checkpoint and ensure that it was successful
	verbose_log "Making checkpoint..."

	
	local CHECKPOINT_OUTPUT=$(run_p4d "-jc -z" true)

	# 2. Ensure the checkpointing was successful
	local JOURNAL_BACKUP_FILE=`sed -nE 's/^Checkpointing to (.+)...$/\1/p' <<< $CHECKPOINT_OUTPUT`
	local CHECKPOINT_REPORTED_MD5=$(parse_md5_file_content "$CHECKPOINT_OUTPUT")
	
	verbose_log "Validating journal file was correctly written to disk..."
	# Validate journal file
	run_p4d "-jv \"$P4ROOT/$JOURNAL_BACKUP_FILE\"" true false
	# 3. Confirm checkpoint was correctly written to disk with md5
	gzip -dk "$P4ROOT/$JOURNAL_BACKUP_FILE"

	local JOURNAL_BACKUP_FILE_WITHOUT_GZ=$P4ROOT/${JOURNAL_BACKUP_FILE%.gz}
	local MD5_FILE_CONTENT=$(parse_md5_file_content "`cat $JOURNAL_BACKUP_FILE_WITHOUT_GZ.md5`")
	if [[ "${MD5_FILE_CONTENT^^}" != "${CHECKPOINT_REPORTED_MD5^^}" ]]; then
		force_exit_msg "MD5 file has become corrupted during write! Aborting backup"
	fi

	verify_checkpoint "$JOURNAL_BACKUP_FILE_WITHOUT_GZ"

	# Remove the extracted file that we used to verify the md5 of
	rm -f "$JOURNAL_BACKUP_FILE_WITHOUT_GZ"

	# 4. Trim down amount of checkpoints stored locally on the server
	# @TODO: IMPLEMENT
	

	# 5. Backup
	# Set correct project in google cloud
	verbose_log "Authenticating with google cloud storage..."
	safe_gcloud "auth login $(get_backup_account_mail) --cred-file=$(gs_backup_account_cred_file)" true
	safe_gcloud "config set project $_GCLOUD_PROJECT"

	local GS_BASE_PATH=$(get_gs_bucket_base_path)

	verbose_log "Sending journals and checkpoints to google cloud..."
	# 	checkpoint + md5, rotated journal file
	safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "$P4ROOT/$JOURNAL_DIR" $GS_BASE_PATH/journals" true
	#	license file
	if [ -f $P4ROOT/license ]; then
		verbose_log "Sending license to google cloud..."
		safe_gcloud "storage cp "$P4ROOT/license" $GS_BASE_PATH/license" true
	fi
	#	versioned files
	verbose_log "Sending content to google cloud..."
	safe_gcloud "storage rsync --delete-unmatched-destination-objects -r "$P4ROOT/$ARCHIVES_DIR" $GS_BASE_PATH/archives" true

	# 6. backup the server.id
	if [ -f $P4ROOT/server.id ]; then
		verbose_log "Sending server.id to google cloud..."
		safe_gcloud "storage cp "$P4ROOT/server.id" $GS_BASE_PATH/server.id" true
	fi

	verbose_log "Nightly backup succeeded"
}

function weekly_verification() {
	require_param "_P4_TICKET" "-t|--p4_ticket"

	# 1. Verify archive files
	run_p4 "verify -q //..."
	# 2. Verify shelved files 
	run_p4 "verify -q -S //..."

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

function gs_file_exists() {
	local GS_FILE="$1"

	gsutil stat $GS_FILE > /dev/null 2>&1
	return $?
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
	if gs_file_exists "$(get_gs_bucket_base_path)/server.id" -eq 0; then
		FILES_TO_FETCH="$(get_gs_bucket_base_path)/server.id"
	fi

	if $FETCH_LICENSE; then
		if gs_file_exists "$(get_gs_bucket_base_path)/license" -eq 0; then
			FILES_TO_FETCH="$FILES_TO_FETCH $(get_gs_bucket_base_path)/license"
		fi
	fi

	# Do we have any files to fetch, then we fetch them
	if [[ "${#FILES_TO_FETCH}" -gt 0 ]]; then
		local GCLOUD_OUTPUT=$(safe_gcloud "storage cp $FILES_TO_FETCH $(get_p4_root)" true)
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
	local BASE_PATH=$(get_gs_bucket_base_path)
	GCLOUD_RESULT=$(safe_gcloud "storage ls $BASE_PATH/journals/" true)
	
	local LATEST_CHECKPOINT=$(echo -e "$GCLOUD_RESULT" | grep -E "^.*\.ckp\.(\d*).*\.gz$" | sort -t . -k 3n | tail -1)
	local LATEST_MD5=$(echo -e "${LATEST_CHECKPOINT%gz}md5")

	local P4ROOT="$(get_p4_root)"
	local P4JOURNAL_DIR="$P4ROOT/$(get_p4_journal_dir)"
	GCLOUD_RESULT=$(safe_gcloud "storage cp $LATEST_CHECKPOINT $LATEST_MD5 $P4JOURNAL_DIR" true)
	
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
	local GS_BASE_PATH=$(get_gs_bucket_base_path)
	local P4ROOT=$(get_p4_root)
	local ARCHIVES_DIR=$(get_p4_archives_dir)

	safe_gcloud "storage rsync -r $GS_BASE_PATH/archives $P4ROOT/$ARCHIVES_DIR" true
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
	safe_gcloud "auth login $(get_backup_account_mail) --cred-file=$(gs_backup_account_cred_file)" true
	safe_gcloud "config set project $_GCLOUD_PROJECT"

	# REQUIRES:
	# 1. Last checkpoint file and .md5 file
	# 2. Backed up versioned files

	# Steps:
	# 1. RECOVER DATABASE
	# 1.1. Stop the p4d server
	verbose_log "Stopping the p4d service..."
	run_p4dctl "stop"
	# 1.2. Rename (or move) the corrupt database (db.*) files
	temporary_backup_bad_db
	# 1.3.1 Restore checkpoint and md5
	local CHECKPOINT_FILE_REF
	fetch_checkpoint_and_md5 CHECKPOINT_FILE_REF
	# 1.3.2 Get the license and server id
	fetch_license_and_server_id "$_FETCH_LICENSE"
	# 1.4. Invoke p4d with the -jr (journal-restore) flag, specifying only your most recent checkpoint as the perforce user
	run_p4d "$_P4_CASE -jr $CHECKPOINT_FILE_REF" true
	set_perforce_permissions "$(get_p4_root)" "-R"
	# 2. Recover versioned files
	fetch_versioned_files
	# 3. Start system again
	run_p4dctl "start"

	# 4. Check your system
	# 4.1 Check lastCheckpointAction when it was completed 
	LAST_CHECKPOINT_ACTION=$(run_p4 "counter lastCheckpointAction" false)
	if ask_yes_no_question "'p4 counter lastCheckpointAction' gave output:\n'$LAST_CHECKPOINT_ACTION'\n after database restore, this is this date and time of last checkpoint, does this look resonable?" -eq "0"; then
		force_exit_msg "Restore was unsuccessful =/... Please do it manually according to: https://www.perforce.com/manuals/p4sag/Content/P4SAG/backup.recovery.damage.html"
	fi

	# 4.2 Verify all files on the depot and all shelved files
	verbose_log "Verifying files to ensure that the backup was successful..."
	run_p4 "verify -q //..."
	# @TODO: Verify that this really works too!
	run_p4 "verify -q -S //..."

	# 5. If everything was successful, then we can delete the corrupted db.* files
	remove_bad_db_backup

	verbose_log "Restoration of db and files complete!"
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
# TLS_CA_File=/etc/pki/tls/certs/ca-bundle.crt


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

	local PERFORCE_TICKET_FILE=/opt/perforce/backup/perforce_ticket.txt

	# Ensure that there is a /opt/perforce/backup directory with correct permissions
	if [ ! -d /opt/perforce/backup ]; then
		mkdir /opt/perforce/backup
		set_perforce_permissions  "/opt/perforce/backup" "-R"
	fi

	cat <<EOF > $PERFORCE_TICKET_FILE
$_P4_TICKET
EOF
	set_perforce_permissions "$PERFORCE_TICKET_FILE"
	# IS HERE! NEED TO ENSURE THAT THE PERFORCE USER CAN READ /etc/pki/tls/certs/ca-bundle.crt

	local MAINTENENCE_USER="perforce"

	# For explaination on crontab, see https://crontab.guru/#02_1_*_*_1-5,0
	local NIGHTLY_MAINTENENCE_TIME="2 1 * * 1-5,0"
	local NIGHTLY_MAINTENENCE_COMMAND="$INSTALLED_PATH --nightly --gcloud_project=$_GCLOUD_PROJECT --gcloud_bucket=$_GCLOUD_BUCKET --gcloud_backup_user=$_GCLOUD_BACKUP_USER -t \`cat $PERFORCE_TICKET_FILE\` -m $_NOTIFICATION_RECIPIENTS"
	
	# For explaination on crontab, see https://crontab.guru/#2_1_*_*_6
	local WEEKLY_MAINTENENCE_TIME="2 1 * * 6"
	local WEEKLY_MAINTENENCE_COMMAND="$INSTALLED_PATH --nightly --weekly --gcloud_project=$_GCLOUD_PROJECT --gcloud_bucket=$_GCLOUD_BUCKET --gcloud_backup_user=$_GCLOUD_BACKUP_USER -t \`cat $PERFORCE_TICKET_FILE\` -m $_NOTIFICATION_RECIPIENTS"

	echo 'MAILTO=""' > "/etc/cron.d/perforce_maintenance"
	echo "$NIGHTLY_MAINTENENCE_TIME $MAINTENENCE_USER $NIGHTLY_MAINTENENCE_COMMAND" >> "/etc/cron.d/perforce_maintenance"
	echo "$WEEKLY_MAINTENENCE_TIME $MAINTENENCE_USER $WEEKLY_MAINTENENCE_COMMAND" >> "/etc/cron.d/perforce_maintenance"

	# @todonow: test nightly + weekly
	safe_command "chmod 640 /etc/cron.d/perforce_maintenance"
	# @TODO: Setup when backupscripts is run, move the backupscript into place etc

	verbose_log "Setup is complete"
}

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