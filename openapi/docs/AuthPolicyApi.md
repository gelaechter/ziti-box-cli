# \AuthPolicyApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_auth_policy**](AuthPolicyApi.md#create_auth_policy) | **POST** /auth-policies | Creates an Auth Policy
[**delete_auth_policy**](AuthPolicyApi.md#delete_auth_policy) | **DELETE** /auth-policies/{id} | Delete an Auth Policy
[**detail_auth_policy**](AuthPolicyApi.md#detail_auth_policy) | **GET** /auth-policies/{id} | Retrieves a single Auth Policy
[**list_auth_policies**](AuthPolicyApi.md#list_auth_policies) | **GET** /auth-policies | List Auth Policies
[**patch_auth_policy**](AuthPolicyApi.md#patch_auth_policy) | **PATCH** /auth-policies/{id} | Update the supplied fields on an Auth Policy
[**update_auth_policy**](AuthPolicyApi.md#update_auth_policy) | **PUT** /auth-policies/{id} | Update all fields on an Auth Policy



## create_auth_policy

> models::CreateEnvelope create_auth_policy(auth_policy)
Creates an Auth Policy

Creates an Auth Policy. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**auth_policy** | [**AuthPolicyCreate**](AuthPolicyCreate.md) | An Auth Policy to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_auth_policy

> models::Empty delete_auth_policy(id)
Delete an Auth Policy

Delete an Auth Policy by id. Requires admin access. 

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


## detail_auth_policy

> models::DetailAuthPolicyEnvelope detail_auth_policy(id)
Retrieves a single Auth Policy

Retrieves a single Auth Policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailAuthPolicyEnvelope**](detailAuthPolicyEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_auth_policies

> models::ListAuthPoliciesEnvelope list_auth_policies(limit, offset, filter)
List Auth Policies

Retrieves a list of Auth Policies

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListAuthPoliciesEnvelope**](listAuthPoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_auth_policy

> models::Empty patch_auth_policy(id, auth_policy)
Update the supplied fields on an Auth Policy

Update only the supplied fields on an Auth Policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**auth_policy** | [**AuthPolicyPatch**](AuthPolicyPatch.md) | An Auth Policy patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_auth_policy

> models::Empty update_auth_policy(id, auth_policy)
Update all fields on an Auth Policy

Update all fields on an Auth Policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**auth_policy** | **models::AuthPolicyCreate** | An Auth Policy update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

