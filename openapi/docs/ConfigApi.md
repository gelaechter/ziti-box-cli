# \ConfigApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_config**](ConfigApi.md#create_config) | **POST** /configs | Create a config resource
[**create_config_type**](ConfigApi.md#create_config_type) | **POST** /config-types | Create a config-type. Requires admin access.
[**delete_config**](ConfigApi.md#delete_config) | **DELETE** /configs/{id} | Delete a config
[**delete_config_type**](ConfigApi.md#delete_config_type) | **DELETE** /config-types/{id} | Delete a config-type
[**detail_config**](ConfigApi.md#detail_config) | **GET** /configs/{id} | Retrieves a single config
[**detail_config_type**](ConfigApi.md#detail_config_type) | **GET** /config-types/{id} | Retrieves a single config-type
[**list_config_services**](ConfigApi.md#list_config_services) | **GET** /configs/{id}/services | List services referenced by a config
[**list_config_types**](ConfigApi.md#list_config_types) | **GET** /config-types | List config-types
[**list_configs**](ConfigApi.md#list_configs) | **GET** /configs | List configs
[**list_configs_for_config_type**](ConfigApi.md#list_configs_for_config_type) | **GET** /config-types/{id}/configs | Lists the configs of a specific config-type
[**patch_config**](ConfigApi.md#patch_config) | **PATCH** /configs/{id} | Update the supplied fields on a config
[**patch_config_type**](ConfigApi.md#patch_config_type) | **PATCH** /config-types/{id} | Update the supplied fields on a config-type
[**update_config**](ConfigApi.md#update_config) | **PUT** /configs/{id} | Update all fields on a config
[**update_config_type**](ConfigApi.md#update_config_type) | **PUT** /config-types/{id} | Update all fields on a config-type



## create_config

> models::CreateEnvelope create_config(config)
Create a config resource

Create a config resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**config** | [**ConfigCreate**](ConfigCreate.md) | A config to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_config_type

> models::CreateEnvelope create_config_type(config_type)
Create a config-type. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**config_type** | [**ConfigTypeCreate**](ConfigTypeCreate.md) | A config-type to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_config

> models::Empty delete_config(id)
Delete a config

Delete a config by id. Requires admin access.

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


## delete_config_type

> models::Empty delete_config_type(id)
Delete a config-type

Delete a config-type by id. Removing a configuration type that are in use will result in a 409 conflict HTTP status code and error. All configurations of a type must be removed first.

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


## detail_config

> models::DetailConfigEnvelope detail_config(id)
Retrieves a single config

Retrieves a single config by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailConfigEnvelope**](detailConfigEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_config_type

> models::DetailConfigTypeEnvelope detail_config_type(id)
Retrieves a single config-type

Retrieves a single config-type by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailConfigTypeEnvelope**](detailConfigTypeEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_config_services

> models::ListServicesEnvelope list_config_services(id, limit, offset, filter)
List services referenced by a config

Retrieves a list of service resources that reference a given config; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListServicesEnvelope**](listServicesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_config_types

> models::ListConfigTypesEnvelope list_config_types(limit, offset, filter)
List config-types

Retrieves a list of config-type resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListConfigTypesEnvelope**](listConfigTypesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_configs

> models::ListConfigsEnvelope list_configs(limit, offset, filter)
List configs

Retrieves a list of config resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListConfigsEnvelope**](listConfigsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_configs_for_config_type

> models::ListConfigsEnvelope list_configs_for_config_type(id)
Lists the configs of a specific config-type

Lists the configs associated to a config-type. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListConfigsEnvelope**](listConfigsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_config

> models::Empty patch_config(id, config)
Update the supplied fields on a config

Update the supplied fields on a config. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**config** | [**ConfigPatch**](ConfigPatch.md) | A config patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_config_type

> models::Empty patch_config_type(id, config_type)
Update the supplied fields on a config-type

Update the supplied fields on a config-type. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**config_type** | [**ConfigTypePatch**](ConfigTypePatch.md) | A config-type patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_config

> models::Empty update_config(id, config)
Update all fields on a config

Update all fields on a config by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**config** | [**ConfigUpdate**](ConfigUpdate.md) | A config update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_config_type

> models::Empty update_config_type(id, config_type)
Update all fields on a config-type

Update all fields on a config-type by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**config_type** | [**ConfigTypeUpdate**](ConfigTypeUpdate.md) | A config-type update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

