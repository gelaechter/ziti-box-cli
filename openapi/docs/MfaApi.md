# \MfaApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**authenticate_mfa**](MfaApi.md#authenticate_mfa) | **POST** /authenticate/mfa | Complete MFA authentication
[**create_mfa_recovery_codes**](MfaApi.md#create_mfa_recovery_codes) | **POST** /current-identity/mfa/recovery-codes | For a completed MFA enrollment regenerate the recovery codes
[**create_totp_token**](MfaApi.md#create_totp_token) | **POST** /current-api-session/totp-token | Create an MFA TOTP token that proves TOTP code checking has passed as a specific time for posture checks.
[**delete_mfa**](MfaApi.md#delete_mfa) | **DELETE** /current-identity/mfa | Disable MFA for the current identity
[**detail_mfa**](MfaApi.md#detail_mfa) | **GET** /current-identity/mfa | Returns the current status of MFA enrollment
[**detail_mfa_qr_code**](MfaApi.md#detail_mfa_qr_code) | **GET** /current-identity/mfa/qr-code | Show a QR code for unverified MFA enrollments
[**detail_mfa_recovery_codes**](MfaApi.md#detail_mfa_recovery_codes) | **GET** /current-identity/mfa/recovery-codes | For a completed MFA enrollment view the current recovery codes
[**enroll_mfa**](MfaApi.md#enroll_mfa) | **POST** /current-identity/mfa | Initiate MFA enrollment
[**remove_identity_mfa**](MfaApi.md#remove_identity_mfa) | **DELETE** /identities/{id}/mfa | Remove MFA from an identitity
[**verify_mfa**](MfaApi.md#verify_mfa) | **POST** /current-identity/mfa/verify | Complete MFA enrollment by verifying a time based one time token



## authenticate_mfa

> models::Empty authenticate_mfa(mfa_auth)
Complete MFA authentication

Completes MFA authentication by submitting a MFA time based one time token or backup code.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_auth** | [**MfaCode**](MfaCode.md) | An MFA validation request | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_mfa_recovery_codes

> models::Empty create_mfa_recovery_codes(mfa_validation)
For a completed MFA enrollment regenerate the recovery codes

Allows regeneration of recovery codes of an MFA enrollment. Requires a current valid time based one time password to interact with. Available after a completed MFA enrollment. This replaces all existing recovery codes. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_validation** | [**MfaCode**](MfaCode.md) | An MFA validation request | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


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


## delete_mfa

> models::Empty delete_mfa(mfa_validation_code)
Disable MFA for the current identity

Disable MFA for the current identity. Requires a current valid time based one time password if MFA enrollment has been completed. If not, code should be an empty string. If one time passwords are not available and admin account can be used to remove MFA from the identity via `DELETE /identities/<id>/mfa`. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_validation_code** | Option<**String**> |  |  |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_mfa

> models::DetailMfaEnvelope detail_mfa()
Returns the current status of MFA enrollment

Returns details about the current MFA enrollment. If enrollment has not been completed it will return the current MFA configuration details necessary to complete a `POST /current-identity/mfa/verify`. 

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::DetailMfaEnvelope**](detailMfaEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_mfa_qr_code

> detail_mfa_qr_code()
Show a QR code for unverified MFA enrollments

Shows an QR code image for unverified MFA enrollments. 404s if the MFA enrollment has been completed or not started. 

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_mfa_recovery_codes

> models::DetailMfaRecoveryCodesEnvelope detail_mfa_recovery_codes(mfa_validation_code, mfa_validation)
For a completed MFA enrollment view the current recovery codes

Allows the viewing of recovery codes of an MFA enrollment. Requires a current valid time based one time password to interact with. Available after a completed MFA enrollment. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_validation_code** | Option<**String**> |  |  |
**mfa_validation** | Option<[**MfaCode**](MfaCode.md)> | An MFA validation request |  |

### Return type

[**models::DetailMfaRecoveryCodesEnvelope**](detailMfaRecoveryCodesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## enroll_mfa

> models::CreateEnvelope enroll_mfa()
Initiate MFA enrollment

Allows authenticator based MFA enrollment. If enrollment has already been completed, it must be disabled before attempting to re-enroll. Subsequent enrollment request is completed via `POST /current-identity/mfa/verify` 

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## remove_identity_mfa

> models::Empty remove_identity_mfa(id)
Remove MFA from an identitity

Allows an admin to remove MFA enrollment from a specific identity. Requires admin. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## verify_mfa

> models::Empty verify_mfa(mfa_validation)
Complete MFA enrollment by verifying a time based one time token

Completes MFA enrollment by accepting a time based one time password as verification. Called after MFA enrollment has been initiated via `POST /current-identity/mfa`. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**mfa_validation** | [**MfaCode**](MfaCode.md) | An MFA validation request | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

