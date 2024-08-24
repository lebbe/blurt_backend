# Messages left-overs:

A message should have a timestamp or zulu-time datetime column.

# Profile!

## GET /profile

gets the logged in user's profile

## GET /profile/id

gets the specified users profile

## POST /profile

posts profile data for user

# Subscribe!

## POST /subscribe/id

subscribes on given user

## DELETE /subscribe/id

unsubscribes given user

## GET /subscriptions

get id and profile name for all subscriptions

# FEED

## GET /feed

get the feed for the logged in user:

latest 40 messages from subscribers
also meta-data on profile name and profile avatar

# Refactor

Perhaps own files for

1. Registration and login
2. Messages
3. Profiles
4. Subscriptions
5. Feed
