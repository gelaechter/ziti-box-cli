# \RouterApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_router**](RouterApi.md#create_router) | **POST** /routers | Create a router resource
[**create_transit_router**](RouterApi.md#create_transit_router) | **POST** /transit-routers | Create a router resource
[**delete_router**](RouterApi.md#delete_router) | **DELETE** /routers/{id} | Delete a router
[**delete_transit_router**](RouterApi.md#delete_transit_router) | **DELETE** /transit-routers/{id} | Delete a router
[**detail_router**](RouterApi.md#detail_router) | **GET** /routers/{id} | Retrieves a single router
[**detail_transit_router**](RouterApi.md#detail_transit_router) | **GET** /transit-routers/{id} | Retrieves a single router
[**list_routers**](RouterApi.md#list_routers) | **GET** /routers | List routers
[**list_transit_routers**](RouterApi.md#list_transit_routers) | **GET** /transit-routers | List routers
[**patch_router**](RouterApi.md#patch_router) | **PATCH** /routers/{id} | Update the supplied fields on a router
[**patch_transit_router**](RouterApi.md#patch_transit_router) | **PATCH** /transit-routers/{id} | Update the supplied fields on a router
[**update_router**](RouterApi.md#update_router) | **PUT** /routers/{id} | Update all fields on a router
[**update_transit_router**](RouterApi.md#update_transit_router) | **PUT** /transit-routers/{id} | Update all fields on a router



## create_router

> models::CreateEnvelope create_router(router)
Create a router resource

Create a router resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**router** | [**RouterCreate**](RouterCreate.md) | A router to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_transit_router

> models::CreateEnvelope create_transit_router(router)
Create a router resource

Create a router resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**router** | [**RouterCreate**](RouterCreate.md) | A router to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_router

> models::Empty delete_router(id)
Delete a router

Delete a router by id. Requires admin access.

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


## delete_transit_router

> models::Empty delete_transit_router(id)
Delete a router

Delete a router by id. Requires admin access.

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


## detail_router

> models::DetailRouterEnvelope detail_router(id)
Retrieves a single router

Retrieves a single router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailRouterEnvelope**](detailRouterEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_transit_router

> models::DetailRouterEnvelope detail_transit_router(id)
Retrieves a single router

Retrieves a single router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailRouterEnvelope**](detailRouterEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_routers

> models::ListRoutersEnvelope list_routers(limit, offset, filter)
List routers

Retrieves a list of router resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoutersEnvelope**](listRoutersEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_transit_routers

> models::ListRoutersEnvelope list_transit_routers(limit, offset, filter)
List routers

Retrieves a list of router resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoutersEnvelope**](listRoutersEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_router

> models::Empty patch_router(id, router)
Update the supplied fields on a router

Update the supplied fields on a router. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**router** | [**RouterPatch**](RouterPatch.md) | A router patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_transit_router

> models::Empty patch_transit_router(id, router)
Update the supplied fields on a router

Update the supplied fields on a router. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**router** | [**RouterPatch**](RouterPatch.md) | A router patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_router

> models::Empty update_router(id, router)
Update all fields on a router

Update all fields on a router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**router** | [**RouterUpdate**](RouterUpdate.md) | A router update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_transit_router

> models::Empty update_transit_router(id, router)
Update all fields on a router

Update all fields on a router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**router** | [**RouterUpdate**](RouterUpdate.md) | A router update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

