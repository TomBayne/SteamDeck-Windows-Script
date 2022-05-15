# SteamDeck-Windows-Script
A PowerShell script that configures Windows to be highly optimised for running from an SD card on the Steam Deck.
Some code has been taken from other open source projects, credits have been given within the code in comments.

## READ!
- I have no real data on how much these optimisations **actualy** improve performance, SD card life, or battery life, however it should *theoretically* make a difference.
- Please create PRs, issues, or discussions on issues with this script, or features that should be included.
- I wrote this script whilst my deck was out for delivery, so I cannot currently test it on an actual deck.

## How to use

1) Run PowerShell as an administrator, and run the command `Set-ExecutionPolicy Unrestricted`
2) Use the `cd` command to move to the location of the script (i.e. `cd C:/Users/tomba/Desktop/script.ps1`)
3) Run the script using `./optimise.ps1`
