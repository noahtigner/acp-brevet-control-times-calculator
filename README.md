# ACP Brevet Control Times Calculator

An improved version of the offical ACP calculator.

## ACP controle times

Controls are points where a rider must obtain proof of passage, and control[e] times are the minimum and maximum times by which the rider must arrive at the location.   

The algorithm for calculating controle times is described here (https://rusa.org/pages/acp-brevet-control-times-calculator). Additional background information is given here (https://rusa.org/pages/rulesForRiders).  

Essentially, each range of control distances has associated minimum and maximum speeds. The algorithm calculates open and close times based on the amount of time spent in each interval, as shown in the links above. A control at 0 km has a close at 1 hour, and a control farther than 120% of the brevet distance is not allowed. Controls between 100% and 120% the distance of the brevet use the brevet's distance for calculations.

For example, on a 300 km brevet, with controls at 0km, 200km, and 300km, we have
    * Open Times: 0km = 0, 200km = 200/34, 300 = 200/34 + 100/32, where 34 and 32 are the associated max        speeds for 0-200km and 200-400km
    * Close Times: 0km = 1 hour, 200km = 200/15, 300km = 200/15 + 100/15, where 34 and 32 are the associated    min speeds for 0-200km and 200-400km

## Use

Build and run a container using the included Dockerfile. At http://0.0.0.0:5000/, choose a brevet distance (miles or km) and start time, and select the controles in either miles or kilometers. The calculator will calculate the open and close times without the page reloading.

The submit button can be used to save the control times to a database.

Users can register, login, and logout. 
Registering successfully will store the user's credentials in the database and return a JSON object including their URI, unique id, username, and hashed password. After registering and logging in, visit http://0.0.0.0:5000/api/token to be issues a token. Only after logging in and being granted a token can the user access the protected resources (shown below).

The display button brings up a page where these values are displayed in a table. Displaying also clears the database or future use. Redirecting back to the calculator from the display page will refresh the page and remove its contents. 

The contents of the database can also be listed in json or csv format. Specify listAll, listOpenOnly, or listCloseOnly. Additionally, specifying an amount or 'top' values to be shown is possible.
For example, after submitting controle times to the database and successfully authenticating, redirect to http://0.0.0.0:5000/listAll/csv?top=1. 

These options can also be selected via a consumer program by accessing port 5001, or http://0.0.0.0:5001 (this feature has been deprecated on this version) 

## Security

This program includes password based authentication as well as token-based authentication. Passwords are hashed and stored securely in the database along the user's name and unique id. Users can register, login, and logout via the  three buttons above the calculator. Tokens are required to access the contents of the database. To get a token, login and then visit http://0.0.0.0:5000/api/token. This token is valid for approximately 60 seconds. CSRF protection is also built in.
 
## Testing

An automated nose test suite is included. Run 'nosetests' to test server-side logic.

Calculations and server-side logic are done with Flask and Python. Javascript and AJAX are used to take input and display output. 

The display button will not function if nothing has been submitted.
The submit button will not work if nothing is there to submit.

The RESTful implementation can be tested by submitting data to the database before accessing http://0.0.0.0:5001. 

Users are not able to access the contents of the database on port 5000 without logging in an being granted a token. Logging out destroys the token.

## Author

Noah Tigner

nzt@cs.uoregon.edu

Created for CIS 330: Software Engineering at The University of Oregon