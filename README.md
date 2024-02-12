# perforce_maintinence

Script for doing the normal maintenance you need to do for perforce

## How to setup
Copy the file to a location on your machine and give it execute permissions

Then run `./perforce_maintenance.sh -i` to start interactive mode. You need to first setup your cloud provider, then your server by answering all question.
Right now interactive mode isn't that smart about what parameters is required so ensure that FIRST run Setup Cloud Provider, then Configure Server.

After that you should be good to run backup.

# NOTE
This will be rewritten in GO when it's been deployed to first user. As I noticed that it's become way to big for a sane bash-script. So it won't be as throughly tested until the go version is released.

## Why go
I want the script to have as few dependencies on the installed machine as possible, so all languages requre installation of some kind of runtime would invalidate this condition. This leaves C++ and Go from the google client library list. And I want to learn go, so that's why I have chosen go.