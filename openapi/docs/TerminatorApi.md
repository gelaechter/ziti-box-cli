# \TerminatorApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_terminator**](TerminatorApi.md#create_terminator) | **POST** /terminators | Create a terminator resource
[**delete_terminator**](TerminatorApi.md#delete_terminator) | **DELETE** /terminators/{id} | Delete a terminator
[**detail_terminator**](TerminatorApi.md#detail_terminator) | **GET** /terminators/{id} | Retrieves a single terminator
[**list_terminators**](TerminatorApi.md#list_terminators) | **GET** /terminators | List terminators
[**patch_terminator**](TerminatorApi.md#patch_terminator) | **PATCH** /terminators/{id} | Update the supplied fields on a terminator
[**update_terminator**](TerminatorApi.md#update_terminator) | **PUT** /terminators/{id} | Update all fields on a terminator



## create_terminator

> models::CreateEnvelope create_terminator(terminator)
Create a terminator resource

Create a terminator resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**terminator** | [**TerminatorCreate**](TerminatorCreate.md) | A terminator to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_terminator

> models::Empty delete_terminator(id)
Delete a terminator

Delete a terminator by id. Requires admin access.

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


## detail_terminator

> models::DetailTerminatorEnvelope detail_terminator(id)
Retrieves a single terminator

Retrieves a single terminator by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailTerminatorEnvelope**](detailTerminatorEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_terminators

> models::ListTerminatorsEnvelope list_terminators(limit, offset, filter)
List terminators

Retrieves a list of terminator resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListTerminatorsEnvelope**](listTerminatorsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_terminator

> models::Empty patch_terminator(id, terminator)
Update the supplied fields on a terminator

Update the supplied fields on a terminator. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**terminator** | [**TerminatorPatch**](TerminatorPatch.md) | A terminator patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_terminator

> models::Empty update_terminator(id, terminator)
Update all fields on a terminator

Update all fields on a terminator by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**terminator** | [**TerminatorUpdate**](TerminatorUpdate.md) | A terminator update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

