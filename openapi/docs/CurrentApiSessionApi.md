# \CurrentApiSessionApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_totp_token**](CurrentApiSessionApi.md#create_totp_token) | **POST** /current-api-session/totp-token | Create an MFA TOTP token that proves TOTP code checking has passed as a specific time for posture checks.
[**current_api_session_delete**](CurrentApiSessionApi.md#current_api_session_delete) | **DELETE** /current-api-session | Logout
[**detail_current_identity_authenticator**](CurrentApiSessionApi.md#detail_current_identity_authenticator) | **GET** /current-identity/authenticators/{id} | Retrieve an authenticator for the current identity
[**extend_current_identity_authenticator**](CurrentApiSessionApi.md#extend_current_identity_authenticator) | **POST** /current-identity/authenticators/{id}/extend | Allows the current identity to recieve a new certificate associated with a certificate based authenticator
[**extend_verify_current_identity_authenticator**](CurrentApiSessionApi.md#extend_verify_current_identity_authenticator) | **POST** /current-identity/authenticators/{id}/extend-verify | Allows the current identity to validate reciept of a new client certificate
[**get_current_api_session**](CurrentApiSessionApi.md#get_current_api_session) | **GET** /current-api-session | Return the current API session
[**list_current_identity_authenticators**](CurrentApiSessionApi.md#list_current_identity_authenticators) | **GET** /current-identity/authenticators | List authenticators for the current identity
[**patch_current_identity_authenticator**](CurrentApiSessionApi.md#patch_current_identity_authenticator) | **PATCH** /current-identity/authenticators/{id} | Update the supplied fields on an authenticator of this identity
[**update_current_identity_authenticator**](CurrentApiSessionApi.md#update_current_identity_authenticator) | **PUT** /current-identity/authenticators/{id} | Update all fields on an authenticator of this identity



## create_totp_token

> models::TotpTokenEnvelope create_totp_token(mfa_validation)
Create an MFA TOTP token that proves TOTP code checking has passed as a specific time for posture checks.

Creates a TOTP token that proves TOTP validation occurred at a specific time. Used in posture response for posture checks. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_validation** | [**MfaCode**](MfaCode.md) | An MFA TOTP validation request | [required] |

### Return type

[**models::TotpTokenEnvelope**](totpTokenEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## current_api_session_delete

> models::Empty current_api_session_delete()
Logout

Terminates the current API session

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_current_identity_authenticator

> models::DetailAuthenticatorEnvelope detail_current_identity_authenticator(id)
Retrieve an authenticator for the current identity

Retrieves a single authenticator by id. Will only show authenticators assigned to the API session's identity.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailAuthenticatorEnvelope**](detailAuthenticatorEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## extend_current_identity_authenticator

> models::IdentityExtendEnrollmentEnvelope extend_current_identity_authenticator(id, extend)
Allows the current identity to recieve a new certificate associated with a certificate based authenticator

This endpoint only functions for certificates issued by the controller. 3rd party certificates are not handled. Allows an identity to extend its certificate's expiration date by using its current and valid client certificate to submit a CSR. This CSR may be passed in using a new private key, thus allowing private key rotation. The response from this endpoint is a new client certificate which the client must  be verified via the /authenticators/{id}/extend-verify endpoint. After verification is completion any new connections must be made with new certificate. Prior to verification the old client certificate remains active.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**extend** | [**IdentityExtendEnrollmentRequest**](IdentityExtendEnrollmentRequest.md) |  | [required] |

### Return type

[**models::IdentityExtendEnrollmentEnvelope**](identityExtendEnrollmentEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## extend_verify_current_identity_authenticator

> models::Empty extend_verify_current_identity_authenticator(id, extend)
Allows the current identity to validate reciept of a new client certificate

After submitting a CSR for a new client certificate the resulting public certificate must be re-submitted to this endpoint to verify receipt. After receipt, the new client certificate must be used for new authentication requests.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**extend** | [**IdentityExtendValidateEnrollmentRequest**](IdentityExtendValidateEnrollmentRequest.md) |  | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_current_api_session

> models::CurrentApiSessionDetailEnvelope get_current_api_session()
Return the current API session

Retrieves the API session that was used to issue the current request

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::CurrentApiSessionDetailEnvelope**](currentApiSessionDetailEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, default

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_current_identity_authenticators

> models::ListAuthenticatorsEnvelope list_current_identity_authenticators(limit, offset, filter)
List authenticators for the current identity

Retrieves a list of authenticators assigned to the current API session's identity; supports filtering, sorting, and pagination.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListAuthenticatorsEnvelope**](listAuthenticatorsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_current_identity_authenticator

> models::Empty patch_current_identity_authenticator(id, authenticator)
Update the supplied fields on an authenticator of this identity

Update the supplied fields on an authenticator by id. Will only update authenticators assigned to the API session's identity. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**authenticator** | [**AuthenticatorPatchWithCurrent**](AuthenticatorPatchWithCurrent.md) | An authenticator patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_current_identity_authenticator

> models::Empty update_current_identity_authenticator(id, authenticator)
Update all fields on an authenticator of this identity

Update all fields on an authenticator by id.  Will only update authenticators assigned to the API session's identity. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**authenticator** | [**AuthenticatorUpdateWithCurrent**](AuthenticatorUpdateWithCurrent.md) | An authenticator put object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

