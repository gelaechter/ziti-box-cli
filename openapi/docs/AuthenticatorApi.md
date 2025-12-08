# \AuthenticatorApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_authenticator**](AuthenticatorApi.md#create_authenticator) | **POST** /authenticators | Creates an authenticator
[**delete_authenticator**](AuthenticatorApi.md#delete_authenticator) | **DELETE** /authenticators/{id} | Delete an Authenticator
[**detail_authenticator**](AuthenticatorApi.md#detail_authenticator) | **GET** /authenticators/{id} | Retrieves a single authenticator
[**list_authenticators**](AuthenticatorApi.md#list_authenticators) | **GET** /authenticators | List authenticators
[**patch_authenticator**](AuthenticatorApi.md#patch_authenticator) | **PATCH** /authenticators/{id} | Update the supplied fields on an authenticator
[**re_enroll_authenticator**](AuthenticatorApi.md#re_enroll_authenticator) | **POST** /authenticators/{id}/re-enroll | Reverts an authenticator to an enrollment
[**request_extend_all_cert_authenticators**](AuthenticatorApi.md#request_extend_all_cert_authenticators) | **POST** /identities/{id}/request-extend | Indicate all certificate authenticators for the identity should be extended and optionally key rolled on next authentication.
[**request_extend_authenticator**](AuthenticatorApi.md#request_extend_authenticator) | **POST** /authenticators/{id}/request-extend | Indicate a certificate authenticator should be extended and optionally key rolled on next authentication.
[**update_authenticator**](AuthenticatorApi.md#update_authenticator) | **PUT** /authenticators/{id} | Update all fields on an authenticator



## create_authenticator

> models::CreateEnvelope create_authenticator(authenticator)
Creates an authenticator

Creates an authenticator for a specific identity. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**authenticator** | [**AuthenticatorCreate**](AuthenticatorCreate.md) | A Authenticator create object | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_authenticator

> models::Empty delete_authenticator(id)
Delete an Authenticator

Delete an authenticator by id. Deleting all authenticators for an identity will make it impossible to log in. Requires admin access. 

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


## detail_authenticator

> models::DetailAuthenticatorEnvelope detail_authenticator(id)
Retrieves a single authenticator

Retrieves a single authenticator by id. Requires admin access.

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


## list_authenticators

> models::ListAuthenticatorsEnvelope list_authenticators(limit, offset, filter)
List authenticators

Returns a list of authenticators associated to identities. The resources can be sorted, filtered, and paginated. This endpoint requires admin access. 

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


## patch_authenticator

> models::Empty patch_authenticator(id, authenticator)
Update the supplied fields on an authenticator

Update the supplied fields on an authenticator by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**authenticator** | [**AuthenticatorPatch**](AuthenticatorPatch.md) | An authenticator patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## re_enroll_authenticator

> models::CreateEnvelope re_enroll_authenticator(id, re_enroll)
Reverts an authenticator to an enrollment

Allows an authenticator to be reverted to an enrollment and allows re-enrollment to occur. On success the  created enrollment record response is provided and the source authenticator record will be deleted. The  enrollment created depends on the authenticator. UPDB authenticators result in UPDB enrollments, CERT authenticators result in OTT enrollments, CERT + CA authenticators result in OTTCA enrollments. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**re_enroll** | [**ReEnroll**](ReEnroll.md) | A reEnrollment request | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## request_extend_all_cert_authenticators

> models::Empty request_extend_all_cert_authenticators(id, request_extend_authenticator)
Indicate all certificate authenticators for the identity should be extended and optionally key rolled on next authentication.

Allows all certificate authenticators on an identity to be flagged for early extension and optionally private  key rolling. Connecting clients will receive flags in their API Session indicating that an early extension is  request and a hint on whether private keys should be rolled. Clients that do not support extension or cannot  roll keys may ignore one or both flags.  If this request is made against an identity with zero certificate authenticators, a 403 will be returned. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**request_extend_authenticator** | [**RequestExtendAuthenticator**](RequestExtendAuthenticator.md) | A request to flag a certificate authenticator for early extension/key rolling. | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## request_extend_authenticator

> models::Empty request_extend_authenticator(id, request_extend_authenticator)
Indicate a certificate authenticator should be extended and optionally key rolled on next authentication.

Allows a certificate authenticator to be flagged for early extension and optionally private key rolling.  Connecting clients will receive flags in their API Session indicating that an early extension is request and a hint on whether private keys should be rolled. Clients that do not support extension or cannot roll keys may ignore one or both flags.  If this request is made against a non-certificate based authenticator, it will return a 403-forbidden error. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**request_extend_authenticator** | [**RequestExtendAuthenticator**](RequestExtendAuthenticator.md) | A request to flag a certificate authenticator for early extension/key rolling. | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_authenticator

> models::Empty update_authenticator(id, authenticator)
Update all fields on an authenticator

Update all fields on an authenticator by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**authenticator** | [**AuthenticatorUpdate**](AuthenticatorUpdate.md) | An authenticator put object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

