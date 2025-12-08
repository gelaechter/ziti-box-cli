# \SessionApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**delete_session**](SessionApi.md#delete_session) | **DELETE** /sessions/{id} | Delete a session
[**detail_session**](SessionApi.md#detail_session) | **GET** /sessions/{id} | Retrieves a single session
[**detail_session_route_path**](SessionApi.md#detail_session_route_path) | **GET** /sessions/{id}/route-path | Retrieves a single session's router path
[**list_sessions**](SessionApi.md#list_sessions) | **GET** /sessions | List sessions



## delete_session

> models::Empty delete_session(id)
Delete a session

Delete a session by id. Requires admin access.

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


## detail_session

> models::DetailSessionManagementEnvelope detail_session(id)
Retrieves a single session

Retrieves a single session by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailSessionManagementEnvelope**](detailSessionManagementEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_session_route_path

> models::DetailSessionRoutePathEnvelope detail_session_route_path(id)
Retrieves a single session's router path

Retrieves a single session's route path by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailSessionRoutePathEnvelope**](detailSessionRoutePathEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_sessions

> models::ListSessionsManagementEnvelope list_sessions(limit, offset, filter)
List sessions

Retrieves a list of active sessions resources; supports filtering, sorting, and pagination. Requires admin access.  Sessions are tied to an API session and are moved when an API session times out or logs out. Active sessions (i.e. Ziti SDK connected to an edge router) will keep the session and API session marked as active. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListSessionsManagementEnvelope**](listSessionsManagementEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

