## Backend

- [x] Recursivly remove roles from users when role is deleted
- [x] Recursivly delete user bound data on user deletion
- [x] Return http status code in base response
- [x] Validate redirect URI (not sure if we already do this) -> Update: We did :3
- [x] Emails are not unique??? -> Fixed
- [x] Require at lease one oauth scope to authorize
- [ ] Add openid well_known page
- [ ] We want dedicated get all routes like for the passkeys
- [x] Audit Logs for Passkeys

## Frontend

- [x] Frontend missing auth flow id
- [x] User roles ~~dropdown~~ -> Selection Popup
- [x] Create / Edit users
- [x] Disable Users
- [x] Registration
- [x] ~~New "Your Profile" page style +~~ edit button
- [x] Tooltips -> "sv-tooltip"
- [x] render invalid ouath url errors -> auto redirect, fine for now
- [ ] raw json viewer -> debug mode???
- [x] show code users used to join in logs
- [x] show code full warning
- [x] add copy join url button to registration codes
- [ ] "notification" popups in the bottom right corner -> success and error messages
- [x] passkey name overflow fix
- [x] display info for system user on oauth screen
- [x] show invalid oauth scopes

## Both

- [ ] ~~Role descriptions~~ Canceled for now.
- [x] Limit registations (registration codes with limited uses and autoroles?)
- [x] System admin settings (limited registrations, disable oauth application create for default users)
- [ ] Pagination

## ???

- [x] OAuth Connection expiery date is not created or calculated correctly (look further into this)
