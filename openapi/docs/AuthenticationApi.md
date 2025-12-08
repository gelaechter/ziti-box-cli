# \AuthenticationApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**authenticate**](AuthenticationApi.md#authenticate) | **POST** /authenticate | Authenticate via a method supplied via a query string parameter
[**authenticate_mfa**](AuthenticationApi.md#authenticate_mfa) | **POST** /authenticate/mfa | Complete MFA authentication



## authenticate

> models::CurrentApiSessionDetailEnvelope authenticate(method, auth)
Authenticate via a method supplied via a query string parameter

Allowed authentication methods include \"password\", \"cert\", and \"ext-jwt\" 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**method** | **String** |  | [required] |
**auth** | Option<[**Authenticate**](Authenticate.md)> |  |  |

### Return type

[**models::CurrentApiSessionDetailEnvelope**](currentApiSessionDetailEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json, default

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


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

