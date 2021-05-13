# WebAppForHomeUse
A web app that helps with every day life. I add to it as I want more functionality.

## Running
* Install the requirements from requirements.txt
* Run `python3 run.py <IP> <PORT>` in the project folder
* It will generate config.yml which will have a random default admin password in it.
  * user: admin
  * password: `<in config.yml>` 
* Login as admin and the default password.

## Adding users
* As the admin, go to settings > Add user
* Enter an invitation key
* The new user goes to `/register`
* The new user will use this invitation key to make an account.