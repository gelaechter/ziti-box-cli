# \PostureChecksApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_posture_check**](PostureChecksApi.md#create_posture_check) | **POST** /posture-checks | Creates a Posture Checks
[**delete_posture_check**](PostureChecksApi.md#delete_posture_check) | **DELETE** /posture-checks/{id} | Deletes an Posture Checks
[**detail_posture_check**](PostureChecksApi.md#detail_posture_check) | **GET** /posture-checks/{id} | Retrieves a single Posture Checks
[**detail_posture_check_type**](PostureChecksApi.md#detail_posture_check_type) | **GET** /posture-check-types/{id} | Retrieves a single posture check type
[**list_posture_check_types**](PostureChecksApi.md#list_posture_check_types) | **GET** /posture-check-types | List a subset of posture check types
[**list_posture_checks**](PostureChecksApi.md#list_posture_checks) | **GET** /posture-checks | List a subset of posture checks
[**patch_posture_check**](PostureChecksApi.md#patch_posture_check) | **PATCH** /posture-checks/{id} | Update the supplied fields on a Posture Checks
[**update_posture_check**](PostureChecksApi.md#update_posture_check) | **PUT** /posture-checks/{id} | Update all fields on a Posture Checks



## create_posture_check

> models::CreateEnvelope create_posture_check(posture_check)
Creates a Posture Checks

Creates a Posture Checks

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**posture_check** | [**PostureCheckCreate**](PostureCheckCreate.md) | A Posture Check to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_posture_check

> models::Empty delete_posture_check(id)
Deletes an Posture Checks

Deletes and Posture Checks by id

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


## detail_posture_check

> models::DetailPostureCheckEnvelope detail_posture_check(id)
Retrieves a single Posture Checks

Retrieves a single Posture Checks by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailPostureCheckEnvelope**](detailPostureCheckEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_posture_check_type

> models::DetailPostureCheckTypeEnvelope detail_posture_check_type(id)
Retrieves a single posture check type

Retrieves a single posture check type by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailPostureCheckTypeEnvelope**](detailPostureCheckTypeEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_posture_check_types

> models::ListPostureCheckTypesEnvelope list_posture_check_types(limit, offset, filter)
List a subset of posture check types

Retrieves a list of posture check types 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListPostureCheckTypesEnvelope**](listPostureCheckTypesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json; charset=utf-8, application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_posture_checks

> models::ListPostureCheckEnvelope list_posture_checks(limit, offset, filter, role_filter, role_semantic)
List a subset of posture checks

Retrieves a list of posture checks 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |
**role_filter** | Option<[**Vec<String>**](String.md)> |  |  |
**role_semantic** | Option<**String**> |  |  |

### Return type

[**models::ListPostureCheckEnvelope**](listPostureCheckEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json; charset=utf-8, application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_posture_check

> models::Empty patch_posture_check(id, posture_check)
Update the supplied fields on a Posture Checks

Update only the supplied fields on a Posture Checks by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**posture_check** | [**PostureCheckPatch**](PostureCheckPatch.md) | A Posture Check patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_posture_check

> models::Empty update_posture_check(id, posture_check)
Update all fields on a Posture Checks

Update all fields on a Posture Checks by id

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**posture_check** | [**PostureCheckUpdate**](PostureCheckUpdate.md) | A Posture Check update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

