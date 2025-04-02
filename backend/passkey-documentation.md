# Passkey Authentication Documentation

## Overview

Passkeys allow users to authenticate without passwords using FIDO2/WebAuthn standards. This document outlines the API routes necessary for implementing passkey authentication in the auth-rs system.

## Routes

### 1. Register Passkey

#### `POST /auth/passkeys/register/start`

Initiates the passkey registration process for a user.

**Request:**
```json
{
  "userId": "UUID"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Passkey registration initiated",
  "data": {
    "challenge": "Base64EncodedChallenge",
    "registrationId": "UUID",
    "publicKey": {
      "rp": {
        "name": "Your Service Name",
        "id": "yourdomain.com"
      },
      "user": {
        "id": "Base64EncodedUserId",
        "name": "user@example.com",
        "displayName": "User's Display Name"
      },
      "challenge": "Base64EncodedChallenge",
      "pubKeyCredParams": [
        {
          "type": "public-key",
          "alg": -7
        }
      ],
      "timeout": 60000,
      "attestation": "direct",
      "authenticatorSelection": {
        "authenticatorAttachment": "platform",
        "requireResidentKey": true,
        "residentKey": "required",
        "userVerification": "preferred"
      }
    }
  }
}
```

#### `POST /auth/passkeys/register/conditional`

Initiates a passkey registration that doesn't require a user account first - useful for new user registration with passkeys.

**Request:**
```json
{
  "userName": "user@example.com",
  "displayName": "User's Display Name"
}
```

**Response:**
Similar to the standard registration flow, but with resident key parameters enforced.

#### `POST /auth/passkeys/register/finish`

Completes the passkey registration process.

**Request:**
```json
{
  "registrationId": "UUID",
  "credential": {
    "id": "CredentialId",
    "rawId": "Base64EncodedRawId",
    "type": "public-key",
    "response": {
      "attestationObject": "Base64EncodedAttestationObject",
      "clientDataJSON": "Base64EncodedClientDataJSON"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Passkey registered successfully",
  "data": {
    "id": "UUID",
    "deviceType": "platform",
    "createdAt": "2023-01-01T12:00:00Z"
  }
}
```

### 2. Authenticate with Passkey

#### `POST /auth/passkeys/authenticate/start`

Initiates the passkey authentication process with a username.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Authentication initiated",
  "data": {
    "challenge": "Base64EncodedChallenge",
    "authenticationId": "UUID",
    "publicKey": {
      "challenge": "Base64EncodedChallenge",
      "rpId": "yourdomain.com",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "Base64EncodedCredentialId"
        }
      ],
      "timeout": 60000,
      "userVerification": "preferred"
    }
  }
}
```

#### `POST /auth/passkeys/authenticate/conditional`

Initiates authentication without requiring a username first (for resident keys).

**Request:**
Empty body or minimal information - no username required.

**Response:**
```json
{
  "success": true,
  "message": "Conditional authentication initiated",
  "data": {
    "challenge": "Base64EncodedChallenge",
    "authenticationId": "UUID",
    "publicKey": {
      "challenge": "Base64EncodedChallenge",
      "rpId": "yourdomain.com",
      "timeout": 60000,
      "userVerification": "required"
    }
  }
}
```

Note the absence of `allowCredentials` - this enables the browser to automatically prompt for any available resident key.

#### `POST /auth/passkeys/authenticate/finish`

Completes the passkey authentication process.

**Request:**
```json
{
  "authenticationId": "UUID",
  "credential": {
    "id": "CredentialId",
    "rawId": "Base64EncodedRawId",
    "type": "public-key",
    "response": {
      "authenticatorData": "Base64EncodedAuthenticatorData",
      "clientDataJSON": "Base64EncodedClientDataJSON",
      "signature": "Base64EncodedSignature",
      "userHandle": "Base64EncodedUserHandle"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Authentication successful",
  "data": {
    "user": {
      "id": "UUID",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "user",
      "createdAt": "2023-01-01T12:00:00Z",
      "passkey_count": 1
    },
    "token": "JWTToken"
  }
}
```

### 3. Manage Passkeys

#### `GET /auth/passkeys`

Retrieves all registered passkeys for the authenticated user.

**Request Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "message": "Passkeys retrieved successfully",
  "data": [
    {
      "id": "UUID",
      "deviceType": "platform",
      "createdAt": "2023-01-01T12:00:00Z"
    },
    {
      "id": "UUID",
      "deviceType": "cross-platform",
      "createdAt": "2023-01-02T12:00:00Z"
    }
  ]
}
```

#### `PATCH /auth/passkeys/:id`

Updates a passkey's metadata.

**Request Headers:**
```
Authorization: Bearer <token>
```

**Request:**
```json
{
  "deviceType": "phone"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Passkey updated successfully",
  "data": {
    "id": "UUID",
    "deviceType": "phone",
    "createdAt": "2023-01-01T12:00:00Z"
  }
}
```

#### `DELETE /auth/passkeys/:id`

Deletes a passkey.

**Request Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "message": "Passkey deleted successfully"
}
```

## Integration with Existing Authentication

### Combined Login Flow

1. User enters email on login page
2. Backend checks if user has passkeys registered
3. If passkeys are registered, offer passkey authentication
4. If passkeys are not registered or user chooses password, proceed with regular login + MFA if enabled
5. For new registrations, offer passkey setup after successful registration

### Resident Key (Usernameless) Flow

1. User visits login page
2. User selects "Sign in with passkey" without entering a username
3. Browser prompts user to select a passkey from available resident keys
4. User is authenticated based on the selected credential

## Implementation Considerations

### Resident Key Support

Resident keys (also called discoverable credentials) offer these benefits:

1. **Usernameless Authentication**: Users can authenticate without typing a username first
2. **Cross-Device Syncing**: Credentials can sync across the user's devices (with platform authenticators)
3. **True Passwordless**: Eliminates all knowledge-based factors from the authentication process

Configuration is controlled through the authenticator selection parameters:

```json
"authenticatorSelection": {
  "authenticatorAttachment": "platform", // or "cross-platform" or undefined to allow both
  "requireResidentKey": true, // Enforce resident key capability
  "residentKey": "required", // Options: "required", "preferred", "discouraged" 
  "userVerification": "preferred" // Options: "required", "preferred", "discouraged"
}
```

### General Considerations

1. **Security**: Passkeys should be stored securely in the database, with public key data properly encoded
2. **User Experience**: Provide clear instructions to users about passkey usage
3. **Browser Compatibility**: Implement graceful degradation for browsers that don't support WebAuthn
4. **Error Handling**: Provide helpful error messages for common issues (e.g., timeout, user cancellation)
5. **Recovery Options**: Ensure users have alternative authentication methods in case they lose access to their passkey device

## Testing

1. Test across multiple browsers and platforms to ensure compatibility
2. Test with both platform authenticators (e.g., Windows Hello, Touch ID) and cross-platform authenticators (e.g., YubiKey)
3. Test registration, authentication, and management flows thoroughly
4. Test error scenarios and edge cases
5. Specifically test resident key functionality across different browsers and platforms

## Example Implementation Notes

1. **Storage Requirements**: Resident keys require more storage on authenticator devices. Some hardware authenticators have limited storage, while platform authenticators generally have no practical limit.

2. **Credential Discovery**: For usernameless authentication, no `allowCredentials` list is provided, allowing the browser to check for any resident credentials that match your Relying Party ID.

3. **WebAuthn Library**: The implementation will use the existing `webauthn-rs` library, which provides a comprehensive API for handling all passkey operations. 