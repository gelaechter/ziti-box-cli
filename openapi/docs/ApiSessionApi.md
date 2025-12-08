# \ApiSessionApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**delete_api_sessions**](ApiSessionApi.md#delete_api_sessions) | **DELETE** /api-sessions/{id} | Deletes an API Sessions
[**detail_api_sessions**](ApiSessionApi.md#detail_api_sessions) | **GET** /api-sessions/{id} | Retrieves a single API Session
[**list_api_sessions**](ApiSessionApi.md#list_api_sessions) | **GET** /api-sessions | List active API sessions



## delete_api_sessions

> models::Empty delete_api_sessions(id)
Deletes an API Sessions

Deletes and API sesion by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_api_sessions

> models::DetailApiSessionEnvelope detail_api_sessions(id)
Retrieves a single API Session

Retrieves a single API Session by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailApiSessionEnvelope**](detailApiSessionEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_api_sessions

> models::ListApiSessionsEnvelope list_api_sessions(limit, offset, filter)
List active API sessions

Returns a list of active API sessions. The resources can be sorted, filtered, and paginated. This endpoint requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListApiSessionsEnvelope**](listApiSessionsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json; charset=utf-8, application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

