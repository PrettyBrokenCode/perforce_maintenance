# perforce_maintinence

Script for doing the normal maintenance you need to do for perforce

## How to setup
Copy the file to a location on your machine and give it execute permissions

Then run `./perforce_maintenance.sh --gcloud_setup` to setup google cloud backend. It will prompt you for more variables if it needs them

Then run `./perforce_maintenance.sh --setup` to setup the computer to hook up the script with crontab. It will prompt you for more variables if it needs them

If you want to seed your google cloud directly without letting the script run, then run `./perforce_maintenance.sh --nightly`. It will prompt you for more variables if it needs them