# \SettingsApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_controller_setting**](SettingsApi.md#create_controller_setting) | **POST** /controller-settings | Create a controller specific setting
[**delete_controller_setting**](SettingsApi.md#delete_controller_setting) | **DELETE** /controller-settings/{id}/effective | Delete a controller setting object
[**detail_controller_setting**](SettingsApi.md#detail_controller_setting) | **GET** /controller-settings/{id} | Retrieves a single controller setting object.
[**detail_controller_setting_effective**](SettingsApi.md#detail_controller_setting_effective) | **GET** /controller-settings/{id}/effective | Retrieves a single controller's effective calculated settings from the instance and global configuration.
[**list_controller_settings**](SettingsApi.md#list_controller_settings) | **GET** /controller-settings | List controller settings
[**patch_controller_setting**](SettingsApi.md#patch_controller_setting) | **PATCH** /controller-settings/{id}/effective | Update the supplied fields on a controller setting object
[**update_controller_setting**](SettingsApi.md#update_controller_setting) | **PUT** /controller-settings/{id}/effective | Update all fields on a controller setting object



## create_controller_setting

> models::CreateEnvelope create_controller_setting(controller_setting)
Create a controller specific setting

Create a new controller specific settings object. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**controller_setting** | [**ControllerSettingCreate**](ControllerSettingCreate.md) | A controller settings object to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_controller_setting

> models::Empty delete_controller_setting(id)
Delete a controller setting object

Delete a controller setting object by id. Requires admin access.

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


## detail_controller_setting

> models::DetailControllerSettingEnvelope detail_controller_setting(id)
Retrieves a single controller setting object.

Retrieves a single controller setting object by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailControllerSettingEnvelope**](detailControllerSettingEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_controller_setting_effective

> models::DetailControllerSettingEffectiveEnvelope detail_controller_setting_effective(id)
Retrieves a single controller's effective calculated settings from the instance and global configuration.

Retrieves a single controller's effective setting object by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailControllerSettingEffectiveEnvelope**](detailControllerSettingEffectiveEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_controller_settings

> models::ListControllerSettingEnvelope list_controller_settings(limit, offset, filter)
List controller settings

Retrieves a list controller settings including the base `global` settings object and any overriding controller specific settings. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListControllerSettingEnvelope**](listControllerSettingEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_controller_setting

> models::Empty patch_controller_setting(id, controller_setting)
Update the supplied fields on a controller setting object

Update the supplied fields on a controller setting object. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**controller_setting** | [**ControllerSettingPatch**](ControllerSettingPatch.md) | A controller setting object patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_controller_setting

> models::Empty update_controller_setting(id, controller_setting)
Update all fields on a controller setting object

Update all fields on a controller setting object by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**controller_setting** | [**ControllerSettingUpdate**](ControllerSettingUpdate.md) | A controller setting update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

