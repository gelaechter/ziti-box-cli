# \EdgeRouterApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_edge_router**](EdgeRouterApi.md#create_edge_router) | **POST** /edge-routers | Create an edge router
[**delete_edge_router**](EdgeRouterApi.md#delete_edge_router) | **DELETE** /edge-routers/{id} | Delete an edge router
[**detail_edge_router**](EdgeRouterApi.md#detail_edge_router) | **GET** /edge-routers/{id} | Retrieves a single edge router
[**list_edge_router_edge_router_policies**](EdgeRouterApi.md#list_edge_router_edge_router_policies) | **GET** /edge-routers/{id}/edge-router-policies | List the edge router policies that affect an edge router
[**list_edge_router_identities**](EdgeRouterApi.md#list_edge_router_identities) | **GET** /edge-routers/{id}/identities | List associated identities
[**list_edge_router_service_edge_router_policies**](EdgeRouterApi.md#list_edge_router_service_edge_router_policies) | **GET** /edge-routers/{id}/service-edge-router-policies | List the service policies that affect an edge router
[**list_edge_router_services**](EdgeRouterApi.md#list_edge_router_services) | **GET** /edge-routers/{id}/services | List associated services
[**list_edge_routers**](EdgeRouterApi.md#list_edge_routers) | **GET** /edge-routers | List edge routers
[**patch_edge_router**](EdgeRouterApi.md#patch_edge_router) | **PATCH** /edge-routers/{id} | Update the supplied fields on an edge router
[**re_enroll_edge_router**](EdgeRouterApi.md#re_enroll_edge_router) | **POST** /edge-routers/{id}/re-enroll | Re-enroll an edge router
[**update_edge_router**](EdgeRouterApi.md#update_edge_router) | **PUT** /edge-routers/{id} | Update all fields on an edge router



## create_edge_router

> models::CreateEnvelope create_edge_router(edge_router)
Create an edge router

Create a edge router resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**edge_router** | [**EdgeRouterCreate**](EdgeRouterCreate.md) | A edge router to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_edge_router

> models::Empty delete_edge_router(id)
Delete an edge router

Delete an edge router by id. Requires admin access.

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


## detail_edge_router

> models::DetailedEdgeRouterEnvelope detail_edge_router(id)
Retrieves a single edge router

Retrieves a single edge router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailedEdgeRouterEnvelope**](detailedEdgeRouterEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_edge_router_policies

> models::ListEdgeRouterPoliciesEnvelope list_edge_router_edge_router_policies(id)
List the edge router policies that affect an edge router

Retrieves a list of edge router policies that apply to the specified edge router.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListEdgeRouterPoliciesEnvelope**](listEdgeRouterPoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_identities

> models::ListIdentitiesEnvelope list_edge_router_identities(id)
List associated identities

Retrieves a list of identities that may access services via the given edge router. Supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListIdentitiesEnvelope**](listIdentitiesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_service_edge_router_policies

> models::ListServicePoliciesEnvelope list_edge_router_service_edge_router_policies(id)
List the service policies that affect an edge router

Retrieves a list of service policies policies that apply to the specified edge router.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListServicePoliciesEnvelope**](listServicePoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_services

> models::ListServicesEnvelope list_edge_router_services(id)
List associated services

Retrieves a list of services that may be accessed via the given edge router. Supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListServicesEnvelope**](listServicesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_routers

> models::ListEdgeRoutersEnvelope list_edge_routers(limit, offset, filter, role_filter, role_semantic)
List edge routers

Retrieves a list of edge router resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |
**role_filter** | Option<[**Vec<String>**](String.md)> |  |  |
**role_semantic** | Option<**String**> |  |  |

### Return type

[**models::ListEdgeRoutersEnvelope**](listEdgeRoutersEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_edge_router

> models::Empty patch_edge_router(id, edge_router)
Update the supplied fields on an edge router

Update the supplied fields on an edge router. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**edge_router** | [**EdgeRouterPatch**](EdgeRouterPatch.md) | An edge router patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## re_enroll_edge_router

> models::Empty re_enroll_edge_router(id)
Re-enroll an edge router

Removes current certificate based authentication mechanisms and reverts the edge router into a state where enrollment must be performed. The router retains all other properties and associations. If the router is currently connected, it will be disconnected and any attemps to reconnect will fail until the enrollment process is completed with the newly generated JWT.  If the edge router has an existing outstanding enrollment JWT it will be replaced. The previous JWT will no longer be usable to complete the enrollment process. 

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


## update_edge_router

> models::Empty update_edge_router(id, edge_router)
Update all fields on an edge router

Update all fields on an edge router by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**edge_router** | [**EdgeRouterUpdate**](EdgeRouterUpdate.md) | An edge router update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

