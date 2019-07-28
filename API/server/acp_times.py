"""
Open and close time calculations
for ACP-sanctioned brevets
following rules described at https://rusa.org/octime_alg.html
and https://rusa.org/pages/rulesForRiders
"""
import arrow

#  Note for CIS 322 Fall 2016:
#  You MUST provide the following two functions
#  with these signatures, so that I can write
#  automated tests for grading.  You must keep
#  these signatures even if you don't use all the
#  same arguments.  Arguments are explained in the
#  javadoc comments.
#

min_speed = {
   range(0, 200):    15,
   range(200, 400):  15,
   range(400, 600):  15,
   range(600, 1000): 11.428,
   range(1000, 1300):13.333 
}

max_speed = {
   range(0, 200):    34,
   range(200, 400):  32,
   range(400, 600):  30,
   range(600, 1000): 28,
   range(1000, 1300):26 
}

# Final brevet closing times
limits = {
   200:  13.5,
   300:  20,
   400:  27,
   600:  40,
   1000: 75
}

def open_time(control_dist_km, brevet_dist_km, brevet_start_time):
   """
   Args:
      control_dist_km:  number, the control distance in kilometers
      brevet_dist_km: number, the nominal distance of the brevet
         in kilometers, which must be one of 200, 300, 400, 600,
         or 1000 (the only official ACP brevet distances)
      brevet_start_time:  An ISO 8601 format date-time string indicating
         the official start time of the brevet
   Returns:
      An ISO 8601 format date string indicating the control open time.
      This will be in the same time zone as the brevet start time.
   """   

   # If a control is past the brevet distance, use the brevet distance's times
   
   if control_dist_km > brevet_dist_km:
      control_dist_km = brevet_dist_km

   # Calculate open time
   remaining = control_dist_km
   time_delta = 0
   for key in max_speed:
      control_length = (key[-1]+1) - key[0]

      if remaining > control_length:
         time_delta += control_length / max_speed[key]
         remaining -= control_length
      else:
         time_delta += remaining / max_speed[key]
         open_time = arrow.get(brevet_start_time)
         open_time = open_time.replace(hours = time_delta)
         return open_time.isoformat()
      

def close_time(control_dist_km, brevet_dist_km, brevet_start_time):
   """
   Args:
      control_dist_km:  number, the control distance in kilometers
         brevet_dist_km: number, the nominal distance of the brevet
         in kilometers, which must be one of 200, 300, 400, 600, or 1000
         (the only official ACP brevet distances)
      brevet_start_time:  An ISO 8601 format date-time string indicating
         the official start time of the brevet
   Returns:
      An ISO 8601 format date string indicating the control close time.
      This will be in the same time zone as the brevet start time.
   """

   # Control at 0 closes after 1 hour
   if(control_dist_km == 0):
      close_time = arrow.get(brevet_start_time)
      close_time = close_time.replace(hours = 1)
      return close_time.isoformat()

   # If overall time limit reached, close at that limit
   if control_dist_km >= brevet_dist_km:
      limit = limits[brevet_dist_km]
      close_time = arrow.get(brevet_start_time)
      close_time = close_time.replace(hours=limit)
      return close_time.isoformat()

   # Calculate close time
   remaining = control_dist_km
   time_delta = 0
   for key in min_speed:
      control_length = (key[-1]+1) - key[0]

      if remaining > control_length:
         time_delta += control_length / min_speed[key]
         remaining -= control_length
      else:
         time_delta += remaining / min_speed[key]
         close_time = arrow.get(brevet_start_time)
         close_time = close_time.replace(hours = time_delta)
         return close_time.isoformat()