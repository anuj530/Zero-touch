#!/bin/bash
#!/bin/zsh
TESTING_MODE="true"
dialogbinary=/usr/local/bin/dialog
dialogcmdfile=/var/tmp/dialog.log
jamfhelper=/Library/Application\ Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper
LocalAdmin="ladmin"
FDE_SETUP_BINARY="/usr/bin/fdesetup"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Version and Jamf Pro Script Parameters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

scriptVersion="1.8.1"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/
scriptLog="${4:-"/var/log/org.simonsfoundation.swiftdialog.log"}"                        # Parameter 4: Script Log Location [ /var/log/org.churchofjesuschrist.log ] (i.e., Your organization's default location for client-side logs)
welcomeDialog="${6:-"userInput"}"                                               # Parameter 6: Welcome dialog [ userInput (default) | video | false ]
completionActionOption="${7:-"Restart Attended"}"                               # Parameter 7: Completion Action [ wait | sleep (with seconds) | Shut Down | Shut Down Attended | Shut Down Confirm | Restart | Restart Attended (default) | Restart Confirm | Log Out | Log Out Attended | Log Out Confirm ]
requiredMinimumBuild="${8:-"disabled"}"                                         # Parameter 8: Required Minimum Build [ disabled (default) | 22D ] (i.e., Your organization's required minimum build of macOS to allow users to proceed; use "22D" for macOS 13.2.x)
outdatedOsAction="${9:-"/System/Library/CoreServices/Software Update.app"}"     # Parameter 9: Outdated OS Action [ /System/Library/CoreServices/Software Update.app (default) | jamfselfservice://content?entity=policy&id=117&action=view ] (i.e., Jamf Pro Self Service policy ID for operating system ugprades)




####################################################################################################
#
# Pre-flight Checks
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
	touch "${scriptLog}"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Script Logging Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
	echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Current Logged-in User Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function currentLoggedInUser() {
	loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
	updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User: ${loggedInUser}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Logging Preamble
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Initiating …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm script is running as root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#if [[ $(id -u) -ne 0 ]]; then
#	updateScriptLog "PRE-FLIGHT CHECK: This script must be run as root; exiting."
#	exit 1
#fi
#


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate Setup Assistant has completed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

while pgrep -q -x "Setup Assistant"; do
	updateScriptLog "PRE-FLIGHT CHECK: Setup Assistant is still running; pausing for 2 seconds"
	sleep 2
done

updateScriptLog "PRE-FLIGHT CHECK: Setup Assistant is no longer running; proceeding …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm Dock is running / user is at Desktop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
	updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are NOT running; pausing for 1 second"
	sleep 1
done

updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are running; proceeding …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate Operating System Version and Build
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${requiredMinimumBuild}" == "disabled" ]]; then
	
	updateScriptLog "PRE-FLIGHT CHECK: 'requiredMinimumBuild' has been set to ${requiredMinimumBuild}; skipping OS validation."
	updateScriptLog "PRE-FLIGHT CHECK: macOS ${osVersion} (${osBuild}) installed"
	
else
	
	# Since swiftDialog requires at least macOS 11 Big Sur, first confirm the major OS version
	# shellcheck disable=SC2086 # purposely use single quotes with osascript
	if [[ "${osMajorVersion}" -ge 11 ]] ; then
		
		updateScriptLog "PRE-FLIGHT CHECK: macOS ${osMajorVersion} installed; checking build version ..."
		
		# Confirm the Mac is running `requiredMinimumBuild` (or later)
		if [[ "${osBuild}" > "${requiredMinimumBuild}" ]]; then
			
			updateScriptLog "PRE-FLIGHT CHECK: macOS ${osVersion} (${osBuild}) installed; proceeding ..."
			
			# When the current `osBuild` is older than `requiredMinimumBuild`; exit with error
		else
			updateScriptLog "PRE-FLIGHT CHECK: The installed operating system, macOS ${osVersion} (${osBuild}), needs to be updated to Build ${requiredMinimumBuild}; exiting with error."
			osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\rExpected macOS Build '${requiredMinimumBuild}' (or newer), but found macOS '${osVersion}' ('${osBuild}').\r\r" with title "Setup Your Mac: Detected Outdated Operating System" buttons {"Open Software Update"} with icon caution'
			updateScriptLog "PRE-FLIGHT CHECK: Executing /usr/bin/open '${outdatedOsAction}' …"
			su - "${loggedInUser}" -c "/usr/bin/open \"${outdatedOsAction}\""
			exit 1
			
		fi
		
		# The Mac is running an operating system older than macOS 11 Big Sur; exit with error
	else
		
		updateScriptLog "PRE-FLIGHT CHECK: swiftDialog requires at least macOS 11 Big Sur and this Mac is running ${osVersion} (${osBuild}), exiting with error."
		osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\rExpected macOS Build '${requiredMinimumBuild}' (or newer), but found macOS '${osVersion}' ('${osBuild}').\r\r" with title "Setup Your Mac: Detected Outdated Operating System" buttons {"Open Software Update"} with icon caution'
		updateScriptLog "PRE-FLIGHT CHECK: Executing /usr/bin/open '${outdatedOsAction}' …"
		su - "${loggedInUser}" -c "/usr/bin/open \"${outdatedOsAction}\""
		exit 1
		
	fi
	
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Ensure computer does not go to sleep during SYM (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Caffeinating this script (PID: $$)"
caffeinate -dimsu -w $$ &



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate Logged-in System Accounts
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Check for Logged-in System Accounts …"
currentLoggedInUser

counter="1"

until { [[ "${loggedInUser}" != "_mbsetupuser" ]] || [[ "${counter}" -gt "180" ]]; } && { [[ "${loggedInUser}" != "loginwindow" ]] || [[ "${counter}" -gt "30" ]]; } ; do
	
	updateScriptLog "PRE-FLIGHT CHECK: Logged-in User Counter: ${counter}"
	currentLoggedInUser
	sleep 2
	((counter++))
	
done

loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | cut -d " " -f 1 )
loggedInUserID=$( id -u "${loggedInUser}" )
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User First Name: ${loggedInUserFirstname}"
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User ID: ${loggedInUserID}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Temporarily disable `jamf` binary check-in (thanks, @mactroll and @cube!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if [ "$TESTING_MODE" = true ]; then
	echo "This is where Jamf Binary check-in will get disabled."
	
elif [ "$TESTING_MODE" = false ]; then
	JAMF_TASKS=/Library/LaunchDaemons/com.jamfsoftware.task.1.plist
	/bin/launchctl bootout system $JAMF_TASKS
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogCheck() {
	
	# Output Line Number in `verbose` Debug Mode
	if [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "PRE-FLIGHT CHECK: # # # SETUP YOUR MAC VERBOSE DEBUG MODE: Line No. ${LINENO} # # #" ; fi
	
	# Get the URL of the latest PKG From the Dialog GitHub repo
	dialogURL=$(curl --silent --fail "https://api.github.com/repos/bartreardon/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
	
	# Expected Team ID of the downloaded PKG
	expectedDialogTeamID="PWA5E9TQ59"
	
	# Check for Dialog and install if not found
	if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then
		
		updateScriptLog "PRE-FLIGHT CHECK: Dialog not found. Installing..."
		
		# Create temporary working directory
		workDirectory=$( /usr/bin/basename "$0" )
		tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )
		
		# Download the installer package
		/usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"
		
		# Verify the download
		teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')
		
		# Install the package if Team ID validates
		if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
			
			/usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
			sleep 2
			dialogVersion=$( /usr/local/bin/dialog --version )
			updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."
			
		else
			
			# Display a so-called "simple" dialog if Team ID fails to validate
			osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Setup Your Mac: Error" buttons {"Close"} with icon caution'
			completionActionOption="Quit"
			exitCode="1"
			quitScript
			
		fi
		
		# Remove the temporary working directory when done
		/bin/rm -Rf "$tempDirectory"
		
	else
		
		updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(dialog --version) found; proceeding..."
		
	fi
	
}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
	dialogCheck
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Complete"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Identify location of jamf binary.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# If the jamf binary is not found, this check will return a
# null value. This null value is used by the CheckCasper
# function, in the "Checking for the jamf binary" section
# of the function.
JamfBinary=$(/usr/bin/which jamf)

if [[ "$JamfBinary" == "" ]] && [[ -e "/usr/sbin/jamf" ]] && [[ ! -e "/usr/local/bin/jamf" ]]; then
	JamfBinary="/usr/sbin/jamf"
elif [[ "$JamfBinary" == "" ]] && [[ ! -e "/usr/sbin/jamf" ]] && [[ -e "/usr/local/bin/jamf" ]]; then
	JamfBinary="/usr/local/bin/jamf"
elif [[ "$JamfBinary" == "" ]] && [[ -e "/usr/sbin/jamf" ]] && [[ -e "/usr/local/bin/jamf" ]]; then
	JamfBinary="/usr/local/bin/jamf"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Operating System, currently logged-in user and default Exit Code
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

osVersion=$( sw_vers -productVersion )
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
reconOptions=""
exitCode="0"
Model="$(/usr/sbin/system_profiler SPHardwareDataType |/usr/bin/awk -F ': ' '/Model Name/ { print $2 }')" # | sed -e 's/^[[:space:]]*//')"
Serial="$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}')"
hardwareUDID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# User Configuration Dialog UI 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

main_message="Over the next 10-20 minutes, we will be installing some additional applications and configuring some settings on your Mac. Feel free to start working while this process completes.Please don’t shut down or restart the Mac while this is in progress.\n \n At the end of this process, you will be asked to logout and log back in."
banner_image_path="/var/tmp/Simons_logo_blue_fullres.png"
#SF_logo="/Users/achokshi/Downloads/Monday-SF-Blue.png"
# Text that will display in the progress bar
INSTALL_COMPLETE_TEXT="Configuration Complete!"


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Policy Variable to Modify
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# The policy array must be formatted "Progress Bar text,customTrigger". These will be
# run in order as they appear below.
POLICY_ARRAY=(
	"Installing Adobe Reader,install-adobereader"
	"Installing Cisco Umbrella,install-umbrella"
	"Installing Dropbox,install-dropbox"
	"Installing Firefox,install-firefox"
	"Installing Google Chrome,install-chrome"
	"Installing LastPass,install-lastpass"
	"Installing Mendeley,install-mendeley"
	"Installing Microsoft Office,install-office"
	"Installing Microsoft Office Auto-Update,install-mau"
	"Installing Mural,install-mural"
	"Installing Nudge,install-nudge"
	"Installing Sentinel One,install-s1"
	"Installing Slack,install-slack"
	"Installing Zoom,install-zoom"
	"Installing Backblaze,install-backblaze"
	"Installing Print Drivers,installRicohPrintDrivers"
)


# Setting the status bar
# Counter is for making the determinate look nice. Starts at one and adds
# more based on EULA, register, or other options.
ADDITIONAL_OPTIONS_COUNTER=0
if [ "$EULA_ENABLED" = true ]; then ((ADDITIONAL_OPTIONS_COUNTER++)); fi
((ADDITIONAL_OPTIONS_COUNTER++))     #Determinate for rosetta
((ADDITIONAL_OPTIONS_COUNTER++))	 #Determinate for installing additional required items.
((ADDITIONAL_OPTIONS_COUNTER++))	 #Determinate for software updates.

# Checking policy array and adding the count from the additional options above.
ARRAY_LENGTH="$((${#POLICY_ARRAY[@]}+ADDITIONAL_OPTIONS_COUNTER))"
echo $ARRAY_LENGTH


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Functions for Jamf Pro Tech Credentials
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


function JamfProCredsAuth(){
	GetJamfProAPIToken() {
		
		# This function uses Basic Authentication to get a new bearer token for API authentication.
		
		# Create base64-encoded credentials from user account's username and password.
		
		encodedCredentials=$(printf "${jamfpro_user}:${jamfpro_password}" | /usr/bin/iconv -t ISO-8859-1 | /usr/bin/base64 -i -)
		
		# Use the encoded credentials with Basic Authorization to request a bearer token
		
		authToken=$(/usr/bin/curl '..%s..' "${jamfpro_url}/api/v1/auth/token" --max-time 2 --retry 0 --connect-timeout 5 --retry-max-time 10  --retry-delay 0 --silent --request POST --header "Authorization: Basic ${encodedCredentials}")
		
		
		# Parse the returned output for the bearer token and store the bearer token as a variable.
		
		if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]; then
			api_token=$(/usr/bin/awk -F \" 'NR==2{print $4}' <<< "$authToken" | /usr/bin/xargs)
		else
			api_token=$(/usr/bin/plutil -extract token raw -o - - <<< "$authToken")
		fi
		
	}
	
	APITokenValidCheck() {
		
		# Verify that API authentication is using a valid token by running an API command
		# which displays the authorization details associated with the current API user. 
		# The API call will only return the HTTP status code.
		
		api_authentication_check=$(/usr/bin/curl --write-out %{http_code} --silent --output /dev/null "${jamfpro_url}/api/v1/auth" --request GET --header "Authorization: Bearer ${api_token}")
		
	}
	
	CheckAndRenewAPIToken() {
		
		# Verify that API authentication is using a valid token by running an API command
		# which displays the authorization details associated with the current API user. 
		# The API call will only return the HTTP status code.
		
		APITokenValidCheck
		
		# If the api_authentication_check has a value of 200, that means that the current
		# bearer token is valid and can be used to authenticate an API call.
		
		
		if [[ ${api_authentication_check} == 200 ]]; then
			
			# If the current bearer token is valid, it is used to connect to the keep-alive endpoint. This will
			# trigger the issuing of a new bearer token and the invalidation of the previous one.
			#
			# The output is parsed for the bearer token and the bearer token is stored as a variable.
			
			authToken=$(/usr/bin/curl "${jamfpro_url}/api/v1/auth/keep-alive" --silent --request POST --header "Authorization: Bearer ${api_token}")
			if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]; then
				api_token=$(/usr/bin/awk -F \" 'NR==2{print $4}' <<< "$authToken" | /usr/bin/xargs)
			else
				api_token=$(/usr/bin/plutil -extract token raw -o - - <<< "$authToken")
			fi
		else
			
			# If the current bearer token is not valid, this will trigger the issuing of a new bearer token
			# using Basic Authentication.
			
			GetJamfProAPIToken
		fi
	}
	
	InvalidateToken() {
		
		# Verify that API authentication is using a valid token by running an API command
		# which displays the authorization details associated with the current API user. 
		# The API call will only return the HTTP status code.
		
		APITokenValidCheck
		
		# If the api_authentication_check has a value of 200, that means that the current
		# bearer token is valid and can be used to authenticate an API call.
		
		if [[ ${api_authentication_check} == 200 ]]; then
			
			# If the current bearer token is valid, an API call is sent to invalidate the token.
			
			authToken=$(/usr/bin/curl "${jamfpro_url}/api/v1/auth/invalidate-token" --silent  --header "Authorization: Bearer ${api_token}" -X POST)
			
			# Explicitly set value for the api_token variable to null.
			
			api_token=""
			
		fi
	}
	#function to ask for tech's jamf credentials.
	function promptCredentials() {	
		#echo "$api_authentication_check"
		if [[ "$api_authentication_check" -eq 401  ]]; then
			credentials=$($dialogpath --title "Jamf Pro Credentials" \
						--titlefont "size=20" \
						--message "Sign-in failed. Please verify your credentials and try again." \
						--messagefont "size=15" \
						--textfield "Username",required \
						--textfield "Password",secured,required \
						--alignment "center" \
						--button2text "Cancel" \
						--button2action \
						--small \
						--icon "none" \
						--json
)
			/bin/echo "$TIMESTAMP Prompted for Jamf credentials."
			userdataexitcode=$?
			/bin/echo "$TIMESTAMP Jamf Credentials error. Prompted for retry."
			#cancel button.
			if [ $userdataexitcode == 2 ]; then
				/bin/echo "$TIMESTAMP Tech cancelled the jamf retry screen. exiting.."
				exit 1
			fi
		else
			credentials=$($dialogpath --title "Jamf Pro Credentials" \
							--titlefont "size=20" \
							--message "Please sign in using your Jamf credentials." \
							--messagefont "size=15" \
							--textfield "Username",required \
							--textfield "Password",secured,required \
							--alignment "center" \
							--button2text "Cancel" \
							--button2action \
							--small \
							--icon "none" \
							--json
							
) 
			credentialsexitcode=$?
			/bin/echo "$TIMESTAMP Prompted for Jamf credentials."
			#echo $userdataexitcode
			#echo "$credentials"
			#cancel button.
			if [ $credentialsexitcode == 2 ]; then
				/bin/echo "$TIMESTAMP Tech pressed cancel button at the Jamf credentials screen. exiting the script with exit code 1. "
				exit 1
			fi
		fi
	}
	
	#function to display an error if tech's jamf credentials are wrong.
	function promptCredentialsError() {	
		credentials=$($dialogpath --title "Jamf Pro Credentials" \
						--titlefont "size=20" \
						--message "Sign-in failed. Please verify your credentials and try again." \
						--messagefont "size=15" \
						--textfield "Username",required \
						--textfield "Password",secured,required \
						--alignment "center" \
						--button2text "Cancel" \
						--button2action \
						--small \
						--icon "none" \
						--json
)
		
		#credentialsexitcode=$?
		/bin/echo "$TIMESTAMP Prompted for Jamf credentials."
		userdataexitcode=$?
		/bin/echo "$TIMESTAMP Jamf Credentials error. Prompted for retry."
		#echo $userdataexitcode
		#echo "$credentials"
		#cancel button.
		if [ $userdataexitcode == 2 ]; then
			/bin/echo "$TIMESTAMP Tech cancelled the jamf retry screen. exiting.."
			exit 1
			
		fi
	}
	
	#function to prompt for the tech to enter the username.
	function collectusername()
	
	{
		askuserName=$($dialogpath --title "User Account Setup" \
							--titlefont "size=20" \
							--message "Enter the username for the account you'd like to create on this Mac.\n\n _The username is the **first part** of the primary email address (e.g. jsmith-guest@simonsfoundation.org becomes jsmith)_"  \
							--messagefont "weight=light,size=15" \
							--alignment "center"  \
							--textfield "Username",required \
							--button1text "Look up" \
							--button2text "Cancel" \
							--infobuttontext "Enter Manually" \
							--button2action \
							--icon "none" \
							--small \
							--json
							
)
				collectUserNameExitCode=$?
				#echo $userdataexitcode
				/bin/echo "$TIMESTAMP Prompted to collect username."
				#cancel button.
				if [ $collectUserNameExitCode == 2 ]; then
					/bin/echo "$TIMESTAMP Tech cancelled the collect username screen. exiting.."
					exit 1
				fi
				
				if [ $collectUserNameExitCode == 3 ]; then
					tech_manual 
					/bin/echo "$TIMESTAMP Enter Manually button pressed. Enabling Manual switch."
					break;
				fi
				}
				
				#Function to get jamf api token based on the tech's jamf credentials.
				function getUserInfoAuthenticated {
					# Explicitly set initial value for the api_token variable to null:
					
					# Explicitly set initial value for the api_token variable to null:
					
					api_token=""
					
					# Explicitly set initial value for the token_expiration variable to null:
					
					token_expiration=""
					
					promptCredentials
					jamfpro_user=$(echo $credentials | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Username'])" )
					jamfpro_password=$(echo $credentials | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Password'])" )
					# If you choose to hardcode API information into the script, set one or more of the following values:
					#
					# The username for an account on the Jamf Pro server with sufficient API privileges
					# The password for the account
					# The Jamf Pro URL
					
					# Set the Jamf Pro URL here if you want it hardcoded.
					jamfpro_url="https://jss.simonsfoundation.org:8443"	    
					
					# Remove the trailing slash from the Jamf Pro URL if needed.
					jamfpro_url=${jamfpro_url%%/}
					
					GetJamfProAPIToken
					CheckAndRenewAPIToken
					sleep 1
					
					if [[ -z "$api_token" ]]; then
						echo "$api_Token"
						#echo "no api token"
						api_authentication_check=400
					else
						CheckAndRenewAPIToken
						echo $api_authentication_check
					fi
					
					until [[ "$api_authentication_check" -eq 200 ]];
					do
						echo $jamfpro_user
						credentials=""
						echo "$api_authentication_check"
						promptCredentialsError
						jamfpro_user=$(echo $credentials | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Username'])" )
						jamfpro_password=$(echo $credentials | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Password'])" )
						GetJamfProAPIToken
						CheckAndRenewAPIToken
					done
					
				}
				getUserInfoAuthenticated 
				}							
				






# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Configurations options
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function config_options(){
	configurationOptions=$($dialogbinary --title "Configuration Options" \
				--titlefont "size=20" \
				--message "Please select the configuration options below" \
				--selecttitle "Options" --selectvalues "Loaner Pool, Shared Device, User Device, Data Restore, Your device" --selectdefault "Loaner Pool" \
				--alignment "center" \
				--button1action \
				--button2text "Cancel" \
				--button2action \
				--icon "none" \
				--json )
			config_options_exit_code=$?
			while : 
			do 
				#ok button action
				if [ $config_options_exit_code == 0 ]; then
					break;
					
				fi
				
				#cancel button.
				if [ $config_options_exit_code == 2 ]; then
					updateScriptLog "Configuration Options: Tech pressed cancelled button. Exiting."
					exit 1
					
				fi
			done
			
			}
	
			
####################################################################################################
#
# Enduser Welcome dialog 
#
####################################################################################################
function logout_timer(){
	$dialogbinary --height 200 --timer 30 \
	--title "logging out" \
	--message "During the logout process, you will be asked to enter your password to enable FileVault on this mac." \
	--messagefont "weight=light,size=15" \
	--alignment "center" \
	--hideicon
	--ontop
	launchctl bootout user/"${loggedInUserID}"
	
}


function enduser_configuration(){
	
	
	# Configure Swift dialog to display the apps installation progress.
	updateScriptLog "Enduser Configuration: Initializing configuration"
	$dialogbinary --title "Welcome to Simons Foundation, $loggedInUserFirstname!" \
	--bannerimage $banner_image_path \
	--titlefont "shadow=false,weight=light,size=30" \
	--message "$main_message" \
	--messagefont "weight=light,size=15" \
	--alignment "center" \
	--height "400" \
	--button1text "Wait!" \
	--button1disabled \
	--progress $ARRAY_LENGTH \
	--helpmessage "Contact IT \n \n it@simonsfoundation.org" & sleep 0.3
	
	dialog_pid=$!
	
	sleep 5
	/bin/echo "progresstext: Getting things ready" >> $dialogcmdfile
	/bin/echo "progress: 1" >> $dialogcmdfile
	sleep 3
	updateScriptLog "Enduser Configuration: Installing Rosetta"
	# Install Rosetta on Macs running Apple Silicon
	OSMajorVersion="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d '.' -f 1)"
	if [[ $OSMajorVersion -ge 11 ]] && [[ "$(/usr/bin/arch)" == "arm64" ]]; then
		
		if [ "$TESTING_MODE" = true ]; then
			/bin/echo "progresstext: Installing Rosetta" >> $dialogcmdfile
			/bin/echo "progress: 1" >> $dialogcmdfile
			sleep 3
			
		elif [ "$TESTING_MODE" = false ]; then
			#((ADDITIONAL_OPTIONS_COUNTER++))
			/bin/echo "progresstext: Installing Rosetta" >> $dialogcmdfile
			/bin/echo "progress: 1" >> $dialogcmdfile
			
			/usr/sbin/softwareupdate --install-rosetta --agree-to-license
		fi
		
		if [[ $? -ne 0 ]]; then
			/bin/echo "Rosetta was not installed successfully."
		fi
	else /bin/echo "Rosetta not required."
		
	fi
	progress_count=1
	updateScriptLog "Enduser Configuration: Running Policy loop"
	#Loop to run policies
	for POLICY in "${POLICY_ARRAY[@]}"; do
		echo "progresstext: $(echo "$POLICY" | cut -d ',' -f1)" >> $dialogcmdfile
		((progress_count++))
		echo $progress_count
		echo "progress: $progress_count" >> $dialogcmdfile
		if [ "$TESTING_MODE" = true ]; then
			sleep 1
		elif [ "$TESTING_MODE" = false ]; then
			"$JamfBinary" policy -event "$(echo "$POLICY" | cut -d ',' -f2)"
			echo "testing"
		fi
	done
	
	
	
	sleep 5
	
	sudo /usr/bin/killall $JamfBinary
	
	sleep 5
	
	#Re-Enable Jamf Recurring check-ins.
	sudo /bin/launchctl bootstrap system $JAMF_TASKS
	#Now we need to run the following policies outside of the policy array. 
	#The reason for running these policies outside of array is, in the following logic, we are simply running Jamf Policy. 
	#Which will pull in all other additional required items such as fonts, application updates, etc. 
	if [ "$TESTING_MODE" = true ]; then
		#((ADDITIONAL_OPTIONS_COUNTER++))
		((progress_count++))
		echo "progress: $progress_count" >> $dialogcmdfile
		echo "progresstext: Installing additional required items" >> $dialogcmdfile
		sleep 3
	elif [ "$TESTING_MODE" = false ]; then
		#((ADDITIONAL_OPTIONS_COUNTER++))
		((progress_count++))
		echo "progress: $progress_count" >> $dialogcmdfile
		echo "progresstext: Installing additional required items" >> $dialogcmdfile
		"$JamfBinary" policy 
	fi
	
	
	#We need to run the Swiftdialog cleanup script outside of the policy array 
	#because it will uninstall the DEPNotify app before it can run the rest of the script.
	#Running SwiftDialog cleanup script.. 
	if [ "$TESTING_MODE" = true ]; then
		#((ADDITIONAL_OPTIONS_COUNTER++))
		echo "progresstext: Cleaning up.." >> $dialogcmdfile
		((progress_count++))
		echo "progress: $progress_count" >> $dialogcmdfile
		sleep 3
	elif [ "$TESTING_MODE" = false ]; then
		#((ADDITIONAL_OPTIONS_COUNTER++))
		echo "progresstext: Cleaning up.." >> $dialogcmdfile
		((progress_count++))
		echo "progress: $progress_count" >> $dialogcmdfile
		updateScriptLog "Enduser Configuration: Running cleanup script"
		"$JamfBinary" policy -event cleanup-swiftdialog-preinstaller
	fi
	
	#Checking for any pending software updates.
	echo "progresstext: Checking for and installing any OS updates..." >> $dialogcmdfile
	((progress_count++))
	echo "progress: $progress_count" >> $dialogcmdfile
	/usr/sbin/softwareupdate -ia
	
	sleep 3
	
	
	updateScriptLog "Enduser Configuration: Completion text"
	/bin/echo "progresstext: $INSTALL_COMPLETE_TEXT" >> $dialogcmdfile
	echo "progress: 100" >> $dialogcmdfile
	
	
	sleep 5
	/bin/echo "--ontop" >> $dialogcmdfile
	/bin/echo "button1text: Logout" >> $dialogcmdfile
	/bin/echo "button1: enable" >> $dialogcmdfile
	/bin/echo "progresstext: Please click on the logout button to finish the process" >> $dialogcmdfile 
	$dialogbinary --notification "Configuration Complete!" --message "Your mac is now configured. Please logout to finish setting up your mac."
	
	wait $dialog_pid
	logout_timer
}

 



	
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# User Account Creation function begins
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

			
			
			
			
dialogpath=/usr/local/bin/dialog
dialogcmdfile=/var/tmp/dialog.log
jamfhelper=/Library/Application\ Support/JAMF/bin/jamfHelper.app/Contents/MacOS/jamfHelper
EmptyValueMsg="You left the previous dialog empty. Values cannot be blank unless otherwise stated. Please try again."
LocalAdmin="ladmin"
OSMajorVersion="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d '.' -f 1)"
Model="$(/usr/sbin/system_profiler SPHardwareDataType |/usr/bin/awk -F ': ' '/Model Name/ { print $2 }')" # | sed -e 's/^[[:space:]]*//')"
Serial="$(ioreg -c IOPlatformExpertDevice -d 2 | awk -F\" '/IOPlatformSerialNumber/{print $(NF-1)}')"
hardwareUDID=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}')
TIMESTAMP=`date "+%Y-%m-%d %H:%M:%S"`
# Signal file for restore. 
signalFile="/tmp/restorerequired"
loanerSignalFile="/tmp/thisisaloanerpoolmachine"

function create_user_account(){										
	
	function userdata()
	{
		/bin/echo "$TIMESTAMP Manual Switch enabled. Prompted for user data screen."
		uservalue=$($dialogpath --title "User Account Setup" \
								--titlefont "size=20" \
								--message "Please fill out the following information to create a user account." \
								----messagefont "weight=light,size=15" \
								--textfield "First name",required \
								--textfield "Last name",required \
								--textfield "Username",required \
								--textfield "Password",secured,required \
								--textfield "Confirm password",secured,required \
								--selecttitle "Computer type" --selectvalues "Temporary-Loaner, Long-term-deployment" --selectdefault "Long-term-deployment" \
								--selecttitle "User account type"  --selectvalues "Standard, Administrator" --selectdefault "Standard" \
								--alignment "center" \
								--button1action \
								--button2text "Cancel" \
								--button2action \
								--icon "none" \
								--json
								)
		userdataexitcode=$?
					
					#echo $userdataexitcode
					while : 
					do 
						FirstName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['First name'])" )
						LastName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Last name'])" )
						UserName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Username'])" | tr '[:upper:]' '[:lower:]' )
						AccountType=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['User account type']['selectedValue'])" )
						
						#ok button action
						if [ $userdataexitcode == 0 ]; then
							break;
							
						fi
						
						#cancel button.
						if [ $userdataexitcode == 2 ]; then
							/bin/echo "$TIMESTAMP Tech cancelled manual user data screen. exiting.."
							exit 1
							
						fi
					done
				}
				
				
				function manualconfirmuservalue()
				{
					/bin/echo "$TIMESTAMP Prompted the Manual confirm screen. "
					while :
					do
						FirstName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['First name'])" )
						LastName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Last name'])" )
						UserName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Username'])" | tr '[:upper:]' '[:lower:]' )
						AccountType=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['User account type']['selectedValue'])" )
						
						manualconfirmuservaluedialog=$($dialogpath --title "Confirm Details" \
--titlefont "size=20" \
--message "First name:  $FirstName \n\n Last name:  $LastName \n\n Username: $UserName \n\n Account type: $AccountType" \
--messagefont "weight=light,size=15" \
--alignment "center" \
--icon "none" \
--small \
--button1text "Looks good!" --button1action \
--button2text "Try again" --button2action \
) 
						manualconfirmuservalueexitcode=$?
						if [  $manualconfirmuservalueexitcode == 2 ]; then
							/bin/echo "$TIMESTAMP Try again button pressed at the manual confirm screen. Prompting for userdata screen."
							tech_manual
						fi
						if [ $manualconfirmuservalueexitcode == 0 ]; then
							/bin/echo "$TIMESTAMP Looks Good button pressed at the manual confirm screen. Continuing.."
							break;
						fi 
					done	
				}
				
				#Function to verify that the both password entered match. 
				function passwordverification()
				{
					while :
					do
						Password1=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Password'])" )
						#echo $Password1	
						Password2=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Confirm password'])" )
						#echo $Password2	
						if [[ $Password1 == $Password2 ]];
						then
							/bin/echo "$TIMESTAMP Confirmed password matches."
							#$dialogpath --title "Success!" --message "Password match!" --alignment "center"
							break;
						else
							$dialogpath --title "Error!" --titlefont "size=20" --message "Password does not match. Please try again!" --messagefont "weight=light,size=15" --alignment "center" --small --icon "none" >&2 
							/bin/echo "$TIMESTAMP Password doesnt match. Prompting for userdata screen again. Retrying.."
							userdata 
							useraccount_to_verify_manual
							userverification
							passwordverification  
						fi
					done
				}
				
				
				#function to verify that the username does not exist in the username list, it is not one of the protected users, the user does not already exists in the local directory or the user does not already have a home directory. 
				function userverification()
				{
					while :
					do
						UserName=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Username'])" | tr '[:upper:]' '[:lower:]' )
						# List of Home Directories
						ListOfDirectories="$(/usr/bin/dscl /Local/Default list /Users NFSHomeDirectory | /usr/bin/awk '{print $2}')"
						
						# Check if home directory is already in use
						for Directory in $ListOfDirectories; do
							if [[ "$Directory" = "/Users/$UserName" ]]; then
								$dialogpath --title "Error!" --titlefont "size=20" --message "Username $UserName already exists. Please try again." --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small 
								/bin/echo "$TIMESTAMP Username $UserName home directory already exists. Prompted for retry."
								userdata 
								useraccount_to_verify_manual
								userverification
							fi
						done
						
						# List of usernames
						ListOfUsernames="$(/usr/bin/dscl /Local/Default list /Users RecordName | /usr/bin/awk '{print $1}')"
						
						# Check if user name is already in use
						for user in $ListOfUsernames; do
							if [[ $user = "$UserName" ]]; then
								$dialogpath --title "Error!" --titlefont "size=20" --message "Username $UserName already exists. Please try again." --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small
								/bin/echo "$TIMESTAMP Username $UserName already in use. Prompted for retry."
								userdata 
								useraccount_to_verify_manual
								userverification
							fi
						done
						
						# List of usernames that are protected
						ListOfProtectedUsernames="guest"
						
						# Check if user name is one of the protected users.
						for user in $ListOfProtectedUsernames; do
							if [[ $user = "$Username" ]]; then
								$dialogpath --title "Error!" --titlefont "size=20" --message "Username $UserName is protected by the OS. Please try again." --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small
								/bin/echo "$TIMESTAMP Username $UserName protected account. Prompted for retry."
								userdata 
								useraccount_to_verify_manual
								userverification
								
							fi
						done
						
						# Check to make sure that the user does not already exist on local directory
						DSCheck="$(/usr/bin/dscl . -list /Users | /usr/bin/grep "$UserName")"
						
						if [ "$DSCheck" = "$UserName" ]; then
							$dialogpath --title "Error!" --titlefont "size=20" --message "The user $UserName already exists in local Directory. \n\n Please delete account via systems Preferences -> Users & Groups." --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small
							/bin/echo "$TIMESTAMP Username $UserName already exists in local directory. Prompted for retry."
							userdata 
							useraccount_to_verify_manual
							userverification
						else
							/bin/echo "$TIMESTAMP Confirmed $UserName does not exist in local directory."
						fi
						
						# Check to make sure that user home folder does not already exist
						if [ -d "/Users/$UserName" ]; then
							$dialogpath --title "Error!" --titlefont "size=20" --message "The path /Users/$UserName already exists. \n\n Please delete account via systems Preferences -> Users & Groups. \n\n Or if it does not exist there, delete/move/rename /Users/$UserName" --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small
							/bin/echo "$TIMESTAMP The path /Users/$UserName already exists. Prompted for retry."
							userdata 
							useraccount_to_verify_manual
							userverification
						else
							break;
							/bin/echo "Confirmed the path /Users/$UserName does not exist."
						fi
					done
				}
				
				function adminpasscollection
				{
					collectadminpass=$($dialogpath --title "Local admin password" \
--titlefont "size=20" \
--message "Please Enter local admin password." \
--messagefont "weight=light,size=15" \
--textfield "Password",secured,required \
--icon "none" \
--small \
--json
)				
					/bin/echo "$TIMESTAMP Prompted to collect ladmin password."
					adminpassword=$(echo $collectadminpass | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Password'])" )
					
					while :
					do
						
						adminpassvarification=$(dscl . authonly $LocalAdmin $adminpassword) 
						#echo $adminpassvarification
						if [ "$adminpassvarification" != "" ]; then
							$dialogpath --title "Error!" --titlefont "size=20" --message "Invalid Password. Please try again." --messagefont "weight=light,size=15" --alignment "center" --small --icon "none" 
							/bin/echo "$TIMESTAMP Invalid password. Prompted for retry."
							adminpasscollection 
						else
							/bin/echo "$TIMESTAMP Successfully verified local admin password. "
							#$dialogpath --title "Error!" --message "Pass Match"
							break;
						fi	
						
					done
				}
				
				function setComputerName()
				{
					
					ComputerType=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Computer type']['selectedValue'])" )
					if [ "$ComputerType" == "Temporary-Loaner" ]; then
						/usr/sbin/scutil --set ComputerName "$UserFullName $Model Loaner"
						/bin/echo "$TIMESTAMP Computer Name set to $UserFullName $Model Loaner"
					else
						/usr/sbin/scutil --set ComputerName "$UserFullName $Model"
						/bin/echo "$TIMESTAMP Computer Name set to $UserFullName $Model"
					fi
					/usr/sbin/scutil --set LocalHostName "$Serial"
					/bin/echo "$TIMESTAMP Computer local hostname set to $Serial"
					/usr/sbin/scutil --set HostName "$Serial"
					/bin/echo "$TIMESTAMP Computer Hostname set to $Serial"
					
				}
				
				function createUser(){
					if [[ -n "$1" ]] && [[ -z "$2" ]] && [[ -z "$3" ]]; then
						/usr/bin/dscl /Local/Default create /Users/"$1"
					elif [[ -n "$1" ]] && [[ -n "$2" ]]&& [[ -n "${3+x}" ]]; then
						/usr/bin/dscl /Local/Default create /Users/"$1" "$2" "$3"
					fi
				}
				
				
				function setupuseraccount()
				{
					UserFullName="$(/bin/echo $FirstName $LastName)"
					AdminStatus=$(echo $uservalue | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['User account type']['selectedValue'])" )
					#echo $UserFullName
					#echo $AdminStatus
					adminpassword=$adminpassword
					VerifiedUserPass=$Password2
					
					if [[ "$OSMajorVersion" -ge 11 ]]; then
						
						# Attributes that all local user records need
						createUser "$UserName"
						createUser "$UserName" UserShell "/bin/bash"
						createUser "$UserName" RealName "$UserFullName"
						#            createUser "$UserName" NFSHomeDirectory "/Users/$UserName" #Taking place after user data has been moved
						createUser "$UserName" AuthenticationHint ""
						createUser "$UserName" dsAttrTypeNative:unlockOptions 0
						createUser "$UserName" dsAttrTypeNative:AvatarRepresentation ""
						createUser "$UserName" dsAttrTypeNative:_writers_unlockOptions "$UserName"
						createUser "$UserName" dsAttrTypeNative:_writers_picture "$UserName"
						createUser "$UserName" dsAttrTypeNative:_writers_jpegphoto "$UserName"
						createUser "$UserName" dsAttrTypeNative:_writers_hint "$UserName"
						createUser "$UserName" dsAttrTypeNative:_writers_UserCertificate "$UserName"
						createUser "$UserName" dsAttrTypeNative:_writers_AvatarRepresentation "$UserName"
						createUser "$UserName" Picture "/Library/User Pictures/Nature/Earth.png" # Attempt to randomize some day
						if [[ $OSMajorVersion -ge 13 ]]; then
							createUser "$UserName" Picture "/Library/User Pictures/Animals/Zebra.heic"
						fi
						
						/usr/bin/dscl /Local/Default passwd /Users/"$UserName" "$VerifiedUserPass"
						
						# List of UIDs over 500
						ListOfUIDs="$(/usr/bin/dscl /Local/Default list /Users UniqueID | /usr/bin/sort -k2 -n | /usr/bin/awk '$2 > 500 {print $2}')"
						
						StarterUID=501
						
						# Determine first available UID over 500
						for AUID in $ListOfUIDs; do
							if [[ $AUID == $StarterUID ]]; then
								StarterUID=$((StarterUID+1))
								AvailableUID=$StarterUID
							else
								AvailableUID=$StarterUID
								break
							fi
						done
						
						createUser "$UserName" UniqueID $AvailableUID
						createUser "$UserName" PrimaryGroupID 20
						
						# Determine admin access
						if [[ "$AdminStatus" = "Administrator" ]]; then
							/usr/sbin/dseditgroup -o edit -a "$UserName" -t user admin
							/bin/echo "$TIMESTAMP Admin rights provided to the user $UserName"
							# There appear to be two groups that you do NOT get added to when going through previous compared to going through Sys Pref GUI:
							# 79(_appserverusr),81(_appserveradm)
						fi
						
					fi
					
					if [[ "$OSMajorVersion" -ge 11 ]]; then
						/usr/sbin/sysadminctl -adminUser "$LocalAdmin" -adminPassword "$adminpassword" -secureTokenOn "$UserName" -password "$VerifiedUserPass"
					fi
					
					VerifiedUserPass=${VerifiedUserPass//&/&amp;}
					VerifiedUserPass=${VerifiedUserPass//</&lt;}
					VerifiedUserPass=${VerifiedUserPass//>/&gt;}
					VerifiedUserPass=${VerifiedUserPass//\"/&quot;}
					VerifiedUserPass=${VerifiedUserPass//\'/&apos;}
					
					adminpassword=${adminpassword//&/&amp;}
					adminpassword=${adminpassword//</&lt;}
					adminpassword=${adminpassword//>/&gt;}
					adminpassword=${adminpassword//\"/&quot;}
					adminpassword=${adminpassword//\'/&apos;}
					
					if [[ "$OSMajorVersion" -ge 11 ]]; then
						/bin/echo "$TIMESTAMP Enabling FileVault2 encryption..."
						/usr/bin/fdesetup enable -inputplist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Password</key>
<string>$adminpassword</string>
<key>UserName</key>
<string>$LocalAdmin</string>
</dict>
</plist>
EOF
					else
						/bin/echo "$TIMESTAMP Enabling FileVault2 encryption..."
						/usr/bin/fdesetup enable -inputplist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>AdditionalUsers</key>
<array>
<dict>
<key>Password</key>
<string>$VerifiedUserPass</string>
<key>UserName</key>
<string>$UserName</string>
</dict>
</array>
<key>Password</key>
<string>$adminpassword</string>
<key>UserName</key>
<string>$LocalAdmin</string>
</dict>
</plist>
EOF
					fi
					
					createUser "$UserName" NFSHomeDirectory "/Users/$UserName"
					/bin/echo "User Home directory created successfully."
					
					
					unset adminpassword
					unset VerifiedUserPass
					
					
				}
				
				function updatecomputerinventory(){
					
					
					$dialogpath --progress 100 --progresstext "Updating jamf inventory. Please wait.." --button1disabled  --title "loading" --titlefont "weight=light,size=20" --message "" --icon "none" --small & sleep 0.3
					#sudo /bin/echo "progress: 100" >> $dialogcmdfile
					sudo /bin/echo "progresstext: Updating jamf inventory. Please wait.." >> $dialogcmdfile
					sleep 2
					
					if [[ "$UserName" != "ladmin" ]] || [[ "$UserName" != "confroom" ]] || [[ "$UserName" != "security" ]] || [[ "$UserName" != "receptiontemp" ]]
					then
						/usr/local/bin/jamf recon -endUsername "$UserName"
					fi
					
					sudo /bin/echo "progress: 100" >> $dialogcmdfile
					sleep 1
					sudo /bin/echo "quit: " >> $dialogcmdfile
					
				}
				
				
				function confirmaccountcreation()
				
				{
					
					DSCheck="$(/usr/bin/dscl . -list /Users | /usr/bin/grep -w "$UserName")"
					if [ "$DSCheck" = "$UserName" ]; then
						/bin/echo "$TIMESTAMP User account $UserName created successfully."
						$dialogpath --notification --title "Success!" --message "The user account for $UserName was successfully created!"
						#$dialogpath --title "Success!" --titlefont "size=20" --message "The user account for $UserName was successfully created!" --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small --button1text "Continue" --button1action				
						sleep 5
						
					else
						/bin/echo "$TIMESTAMP Error creating $UserName user account. Prompted for a retry."
						$dialogpath --title "Error!" --titlefont "size=20" --message "Error occured!" --messagefont "weight=light,size=15" --alignment "center" --icon "none" --small --button1text "Retry" --button1action	
						if [ $? == 0 ]; then
							tech_manual 
						fi 
					fi
				}
				
				userdata 
				userverification
				passwordverification
				manualconfirmuservalue
				adminpasscollection
				
				
				setupuseraccount 
				setComputerName
				updatecomputerinventory
				confirmaccountcreation
				
				
			}
			
			
			
					
			
			# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
			# User Account Creation function ends
			# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
			#####################################################  Restore Script for Manual function #########################################################################################
			function data_restore(){
				create_user_account 
				LoggedInUser="$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }')"
				
				RsyncLog="/Users/$LoggedInUser/Desktop/rsync_restore.log"
				# Path to Rsync Log
				RsyncLog="/Users/$LoggedInUser/Desktop/rsync_restore.log"
				
				# Path to rsync exclude file
				RsyncExcludeListPath="/tmp/RsyncExcludeList.txt"
				
				# Rsync exclude file contents
				RsyncExcludeList="Dropbox (Simons Foundation)
.dropbox
.Trash
Library/Caches/com.apple.Safari
Library/Caches/Google
Library/Caches/Firefox
Library/Containers/com.microsoft.Excel
Library/Containers/com.microsoft.Powerpoint
Library/Containers/com.microsoft.Word
Library/Containers/com.microsoft.errorreporting
Library/Containers/com.microsoft.Office365ServiceV2
Library/Group Containers/UBF8T346G9.ms
Library/Group Containers/UBF8T346G9.OfficeOsfWebHost"
				
				
				# Path to message
				MailMsg="/tmp/message.txt"
				
				LoggedInUserID=$(/usr/bin/id -u "$LoggedInUser")
				# Determine launchctl method we will need to use to launch osascript under user context
				if [[ "$OSMajorVersion" -eq 10 && "$OSMinorVersion" -le 9 ]]; then
					LID=$(/usr/bin/pgrep -x -u "$LoggedInUserID" loginwindow)
					LMethod="bsexec"
				else
					LID=$LoggedInUserID
					LMethod="asuser"
				fi
				
				# Function to erase keychain items relevant to Office
				function createUserLaunchAgentToDeleteKeychainItems(){
					
					if [[ ! -d "/Users/$UserName/Library/LaunchAgents/" ]]; then
						/bin/mkdir -p "/Users/$UserName/Library/LaunchAgents/"
					fi
					
					LaunchDaemon="org.simonsfoundation.unlicense_office"
					
					echo "<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>"$LaunchDaemon"</string>
	<key>Program</key>
		<string>/bin/zsh</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/zsh</string>
		<string>-c</string>
		<string>/usr/bin/security delete-internet-password -s 'msoCredentialSchemeADAL';
				/usr/bin/security delete-internet-password -s 'msoCredentialSchemeLiveId';
				/usr/bin/security delete-generic-password -l 'Microsoft Office Identities Settings 2';
				/usr/bin/security delete-generic-password -l 'Microsoft Office Identities Settings 3';
				/usr/bin/security delete-generic-password -l 'Microsoft Office Identities Cache 2';
				/usr/bin/security delete-generic-password -l 'Microsoft Office Identities Cache 3';
				/usr/bin/security delete-generic-password -l 'Microsoft Office Ticket Cache';
				/usr/bin/security delete-generic-password -l 'com.microsoft.adalcache';
				/usr/bin/security delete-generic-password -l 'MicrosoftOfficeRMSCredential';
				/usr/bin/security delete-generic-password -l 'MSProtection.framework.service';
				/usr/bin/security delete-generic-password -G 'MSOpenTech.ADAL.1';
				/usr/bin/security delete-generic-password -G 'MSOpenTech.ADAL.1';
				/usr/bin/security delete-generic-password -G 'MSOpenTech.ADAL.1';
				/usr/bin/security delete-generic-password -G 'MSOpenTech.ADAL.1';
				/usr/bin/security delete-generic-password -s 'Adobe User Info';
				/usr/bin/security delete-generic-password -s 'Adobe User OS Info';
				/bin/rm -f "/Users/$UserName/Library/LaunchAgents/$LaunchDaemon".plist;
				/bin/launchctl bootout gui/"$(/usr/bin/id -u $UserName)"/"$LaunchDaemon";</string>
	</array>
	<key>RunAtLoad</key>
		<true/>
	<key>LimitLoadToSessionType</key>
		<string>Aqua</string>
</dict>
</plist>" > /Users/$UserName/Library/LaunchAgents/$LaunchDaemon.plist
				}
				
				
				function homeSourceRequest(){
					FileRequest=$(/bin/launchctl $LMethod $LID /usr/bin/osascript << EOT
	set FileNameASPath to (choose folder with prompt "Please choose the source home directory to copy from:" default location "/Volumes")
	set FileNamePOSIXPath to POSIX path of FileNameASPath
EOT
)
					
					# If user clicks Cancel, exit script
					if [[ $? = 1 ]]; then
						cancel
					fi
					
					#file_name="$(/bin/echo "$FileRequest" | /usr/bin/awk -F / '{ print $(NF-1) }')"
					#echo $file_name
				}
				
				# Function to verify path for volume to sync to new computer, used as a workaround from volume-copying issue
				function verifyHomeSourcePath(){
					CorrectFileRequest=$(/bin/launchctl $LMethod $LID /usr/bin/osascript << EOT
	set FileNameAsPath to text returned of (display dialog "Please verify that this is the path of the source Home Folder you want to use. Make sure there are no strange special characters (excluding the forward slash /) that should not appear in the path." default answer "$FileRequest" with title "Verify Path" buttons {"Continue", "Cancel"} default button 1)
	set FileNamePOSIXPath to POSIX path of FileNameAsPath
EOT
)
					
					# If user clicks Cancel, exit script
					if [[ $? != 0 ]]; then
						exit 1
					fi
					
				}
				function data_transfer()
				
				{
					$dialogpath --progress 100 --progresstext "Transferring Data" --button1disabled  --title "loading" --titlefont "weight=light,size=20" --message "" --icon "none" --small & sleep 0.3
					sudo /bin/echo "progresstext: Data transfer in progress.." >> $dialogcmdfile
					sleep 2
					
					# Creating Rsync Log
					/usr/bin/touch "$RsyncLog"
					
					# Open log in Console
					#/bin/launchctl $LMethod $LID /usr/bin/open -a "$ConsoleApp" "$RsyncLog"
					
					
					# Adding time stamps and hardware info in the beginning of rsync log
					/bin/echo "----------" > "$RsyncLog"
					# Calculating time in epoch seconds to use for calculating start time and run time
					start_time_secs="$(date -u +%s)"
					/bin/echo "START TIME: $(date -r "$start_time_secs")" >> "$RsyncLog"
					/bin/echo "TRANSFERRING DATA FOR USERNAME: $UserName" >> "$RsyncLog"
					/bin/echo " " >> "$RsyncLog" >> "$MailMsg"
					/bin/echo "SOURCE PATH: $CorrectFileRequest" >> "$RsyncLog"
					/bin/echo "DESTINATION PATH: /Users/$UserName" >> "$RsyncLog"
					/bin/echo " " >> "$RsyncLog"
					/bin/echo "DESTINATION HARDWARE SERIAL NUMBER: $Serial" >> "$RsyncLog"
					/bin/echo "DESTINATION HARDWARE MODEL: $Model" >> "$RsyncLog"
					/bin/echo " " >> "$RsyncLog"
					/bin/echo "Calculating space requirements. This may take some time depending on the number of files and size of the source path. Please be patient." >> "$RsyncLog"
					
					# Calculating size of source path
					SourcePathSizeInKB="$(/usr/bin/du -hsk -I "Dropbox (Simons Foundation)" -I ".dropbox" -I ".Trash" -I "Library/Caches/com.apple.Safari" -I "Library/Caches/Google" -I "Library/Caches/Firefox" "$CorrectFileRequest" | /usr/bin/awk '{print $1}')"
					SourcePathSizeInGB="$(echo "scale=2;$SourcePathSizeInKB / 1000000" | /usr/bin/bc)"
					SourcePathSizeInBytes="$(echo "scale=2;$SourcePathSizeInKB * 1000" | /usr/bin/bc)"
					
					# Calculating free space of destination volume
					DestinationFreeSpaceInBytes="$(/usr/libexec/PlistBuddy -c "Print :0:_items:0:free_space_in_bytes" /dev/stdin <<< $(/usr/sbin/system_profiler SPStorageDataType -xml))"
					DestinationFreeSpaceInGB="$(echo "scale=2;$DestinationFreeSpaceInBytes / 1000000000" | /usr/bin/bc)"
					
					/bin/echo "SOURCE SIZE: $SourcePathSizeInGB GB" >> "$RsyncLog"
					/bin/echo "DESTINATION SIZE: $DestinationFreeSpaceInGB GB" >> "$RsyncLog"
					/bin/echo "----------" >> "$RsyncLog"
					
					# Compare free space on destination device to required space needed for data transfer
					if [[ "$SourcePathSizeInBytes" -lt "$DestinationFreeSpaceInBytes" ]]; then
						if [[ -d "$CorrectFileRequest" ]]; then
							/bin/echo "Copying user home directory."
							echo "$RsyncExcludeList" > "$RsyncExcludeListPath"
							# /usr/bin/caffeinate -i /usr/bin/rsync -rlptE --log-file="$RsyncLog" "$CorrectFileRequest"/ "/Users/$Username" --exclude="Dropbox (Simons Foundation)" --exclude=.dropbox --exclude=.Trash --exclude=Library/Caches/com.apple.Safari --exclude=Library/Caches/Google --exclude=Library/Caches/Firefox --exclude=Library/Containers/com.microsoft.Excel --exclude=Library/Containers/com.microsoft.Powerpoint --exclude=Library/Containers/com.microsoft.Word --exclude=Library/Containers/com.microsoft.errorreporting --exclude=Library/Containers/com.microsoft.Office365ServiceV2 --exclude=Library/Group Containers/UBF8T346G9.ms --exclude=Library/Group Containers/UBF8T346G9.OfficeOsfWebHost
							/usr/bin/caffeinate -i /usr/bin/rsync -rlptE --log-file="$RsyncLog" "$CorrectFileRequest"/ "/Users/$UserName" --exclude-from="$RsyncExcludeListPath"
							#                                             -rlp  av
							#                                              rlpt   goD
							#     plarv
						else
							/bin/echo "FAILED RESTORE: SOURCE PATH DOES NOT EXIST - $CorrectFileRequest" >> "$RsyncLog"
							DelayCancel="1"
						fi
					else
						/bin/echo "FAILED RESTORE: INSUFFICIENT FREE SPACE." >> "$RsyncLog"
						DelayCancel="1"
					fi
					
					# Adding time stamps at the end of rsync log
					# Calculating time in epoch seconds to use for calculating end time and run time
					/bin/echo "----------" >> "$RsyncLog"
					EndTimeSecs="$(date -u +%s)"
					/bin/echo "END TIME: $(date -r "$EndTimeSecs")" >> "$RsyncLog"
					/bin/echo "RUN TIME: $(date -u -r $(($EndTimeSecs-$start_time_secs)) +"%H hour(s) %M minute(s) %S second(s)")" >> "$RsyncLog"
					/bin/echo "----------" >> "$RsyncLog"
					
					RsyncLogFinalName="$(/bin/echo $RsyncLog | /usr/bin/cut -d . -f 1)"
					FinalTimestamp="$(/bin/date +%y%m%d%H%M%S)"
					RsyncLogFinalName="$RsyncLogFinalName"_"$FinalTimestamp"
					
					# For mail message
					/bin/echo "See the attached log for full details." > "$MailMsg"
					/bin/echo "----------" >> "$MailMsg"
					# Calculating time in epoch seconds to use for calculating start time and run time
					/bin/echo "START TIME: $(date -r "$start_time_secs")" >> "$MailMsg"
					/bin/echo "TRANSFERRING DATA FOR USERNAME: $UserName" >> "$MailMsg"
					/bin/echo " " >> "$MailMsg"
					/bin/echo "SOURCE PATH: $CorrectFileRequest" >> "$MailMsg"
					/bin/echo "DESTINATION PATH: /Users/$UserName" >> "$MailMsg"
					/bin/echo " " >> "$MailMsg"
					/bin/echo "DESTINATION HARDWARE SERIAL NUMBER: $Serial" >> "$MailMsg"
					/bin/echo "DESTINATION HARDWARE MODEL: $Model" >> "$MailMsg"
					/bin/echo " " >> "$MailMsg"
					/bin/echo "SOURCE SIZE: $SourcePathSizeInGB GB" >> "$MailMsg"
					/bin/echo "DESTINATION SIZE: $DestinationFreeSpaceInGB GB" >> "$MailMsg"
					/bin/echo " " >> "$MailMsg"
					/bin/echo "END TIME: $(date -r "$EndTimeSecs")" >> "$MailMsg"
					/bin/echo "RUN TIME: $(date -u -r $(($EndTimeSecs-$start_time_secs)) +"%H hour(s) %M minute(s) %S second(s)")" >> "$MailMsg"
					
					# Kill Console window
					#/usr/bin/killall "Console"
					
					# Rename rsync log
					/bin/mv "$RsyncLog" "$RsyncLogFinalName".log
					
					# Open final rsync log
					#/bin/launchctl $LMethod $LID /usr/bin/open -a "$ConsoleApp" "$RsyncLogFinalName".log
					
					# Send email message
					# Function to download and decompress tar.gz
					function download(){
						url="${1}"
						name="${2}"
						
						cd /private/tmp
						/usr/bin/curl -O -L ${url}/${name}
						
						name_of_tar_dir="$(/usr/bin/tar -tf $name | /usr/bin/head -n 1 | /usr/bin/awk -F '/' '{print $1}')"
						
						/usr/bin/tar -xzf $name
						cd $name_of_tar_dir
					}
					
					download "https://github.com/muquit/mailsend-go/releases/download/v1.0.10/" "mailsend-go_1.0.10_mac-64bit.tar.gz"
					
					# Use mailsend-go to send email message on success/failure of restore
					# This code will only work on-site in the office
					
					# Do not attach log file if it is bigger than 25MB
					if [[ "$(/usr/bin/du -k "$RsyncLogFinalName.log" | /usr/bin/awk '{print $1}')" -lt 25000 ]]; then
						Attach="attach -file "$RsyncLogFinalName".log"
					else
						/bin/echo "" >> "$MailMsg"
						/bin/echo "Log file too large to include in message." >> "$MailMsg"
					fi
					
					if [[ $DelayCancel == 1 ]]; then
						# Send failure message
						# Because we're using eval to evaluate variables, spaces need to be escaped
						eval ./mailsend-go --smtp smtp-relay.gmail.com -port 465 -subject "Data\ Restore\ Failure\ For:\ $UserName" -from 'noreply@simonsfoundation.org' -to "u5e9y6z6a1e2g6o3@simonsfoundation.slack.com" -domain "simonsfoundation.org" -ssl body -file "$MailMsg" "${Attach}"
						
						# Delete user account
						if [[ -n "$UserName" ]]; then
							/usr/bin/dscl . delete /Users/"$UserName"
							/bin/rm -rf /Users/"$UserName"
						fi
						
						/bin/echo "Restore for /Users/$UserName was unsuccessful."
					else
						# Send success message
						# Because we're using eval to evaluate variables, spaces need to be escaped
						eval ./mailsend-go --smtp smtp-relay.gmail.com -port 465 -subject "Data\ Restore\ Complete\ For:\ $userName" -from 'noreply@simonsfoundation.org' -to "u5e9y6z6a1e2g6o3@simonsfoundation.slack.com" -domain "simonsfoundation.org" -ssl body -file "$MailMsg" "${Attach}"
						createUserLaunchAgentToDeleteKeychainItems
						
						# Set permissions on user home directory
						/usr/sbin/chown -R "$UserName":staff "/Users/$UserName"
						
						# Finish creating user account
						createUser "$UserName" NFSHomeDirectory "/Users/$UserName"
						
						/bin/echo "Restore to /Users/$UserName has been completed."
					fi
					
					# Fix user permissions
					/bin/echo "Fixing user home permissions" >> "$RsyncLogFinalName".log 
					/usr/sbin/diskutil resetUserPermissions / $(/usr/bin/id -u "$UserName")
					
					# Remove Time Machine-related extended attributes
					/usr/bin/xattr -r -d "com.apple.timemachine.private.directorycompletiondate" /Users/"$UserName"
					/usr/bin/xattr -r -d "com.apple.metadata:_kTimeMachineOldestSnapshot" /Users/"$UserName"
					
					
					
					# Re-enable Spotlight Indexing
					/usr/bin/mdutil -a -i on
					
					$dialogpath --notification --title "Success!" --message "Data restore for $UserName was successfully completed!"

					sudo /bin/echo "progress: 100" >> $dialogcmdfile
					sleep 3
					sudo /bin/echo "quit: " >> $dialogcmdfile
					
					
					
					
				}
				
				
				
				#####################################################  Restore Script for Manual function ends #########################################################################################
				homeSourceRequest
				verifyHomeSourcePath
				data_transfer 
				
			}
			
			
			function options_manager(){
				selectedconfigurationOptions=$(echo $configurationOptions | /usr/local/bin/managed_python3 -c "import sys, json; print(json.load(sys.stdin)['Options']['selectedValue'])" 2>/dev/null ) 
				updateScriptLog "Configuration Options: Tech Selected '$selectedconfigurationOptions'."
				
				
				if [[ $selectedconfigurationOptions == "Loaner Pool" ]]; then 
					echo "Running loaner pool configs."
					#confiuration_loanerPool
				fi
				
				if [[ $selectedconfigurationOptions == "User Device" ]]; then
					create_user_account
					enduser_configuration
				fi
				
				if [[ $selectedconfigurationOptions == "Data Restore" ]]; then
					data_restore 
					enduser_configuration
				fi
				if [[ $selectedconfigurationOptions == "Your device" ]]; then 
					enduser_configuration
					echo "Running enduser config"
				fi
			}
			
JamfProCredsAuth			
config_options			
options_manager 
