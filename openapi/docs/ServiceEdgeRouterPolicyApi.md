# \ServiceEdgeRouterPolicyApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_service_edge_router_policy**](ServiceEdgeRouterPolicyApi.md#create_service_edge_router_policy) | **POST** /service-edge-router-policies | Create a service edge router policy resource
[**delete_service_edge_router_policy**](ServiceEdgeRouterPolicyApi.md#delete_service_edge_router_policy) | **DELETE** /service-edge-router-policies/{id} | Delete a service edge policy
[**detail_service_edge_router_policy**](ServiceEdgeRouterPolicyApi.md#detail_service_edge_router_policy) | **GET** /service-edge-router-policies/{id} | Retrieves a single service edge policy
[**list_service_edge_router_policies**](ServiceEdgeRouterPolicyApi.md#list_service_edge_router_policies) | **GET** /service-edge-router-policies | List service edge router policies
[**list_service_edge_router_policy_edge_routers**](ServiceEdgeRouterPolicyApi.md#list_service_edge_router_policy_edge_routers) | **GET** /service-edge-router-policies/{id}/edge-routers | List the edge routers that a service edge router policy applies to
[**list_service_edge_router_policy_services**](ServiceEdgeRouterPolicyApi.md#list_service_edge_router_policy_services) | **GET** /service-edge-router-policies/{id}/services | List the services that a service edge router policy applies to
[**patch_service_edge_router_policy**](ServiceEdgeRouterPolicyApi.md#patch_service_edge_router_policy) | **PATCH** /service-edge-router-policies/{id} | Update the supplied fields on a service edge policy
[**update_service_edge_router_policy**](ServiceEdgeRouterPolicyApi.md#update_service_edge_router_policy) | **PUT** /service-edge-router-policies/{id} | Update all fields on a service edge policy



## create_service_edge_router_policy

> models::CreateEnvelope create_service_edge_router_policy(policy)
Create a service edge router policy resource

Create a service edge router policy resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**policy** | [**ServiceEdgeRouterPolicyCreate**](ServiceEdgeRouterPolicyCreate.md) | A service edge router policy to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_service_edge_router_policy

> models::Empty delete_service_edge_router_policy(id)
Delete a service edge policy

Delete a service edge policy by id. Requires admin access.

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


## detail_service_edge_router_policy

> models::DetailServiceEdgePolicyEnvelope detail_service_edge_router_policy(id)
Retrieves a single service edge policy

Retrieves a single service edge policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailServiceEdgePolicyEnvelope**](detailServiceEdgePolicyEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_edge_router_policies

> models::ListServiceEdgeRouterPoliciesEnvelope list_service_edge_router_policies(limit, offset, filter)
List service edge router policies

Retrieves a list of service edge router policy resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListServiceEdgeRouterPoliciesEnvelope**](listServiceEdgeRouterPoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_edge_router_policy_edge_routers

> models::ListEdgeRoutersEnvelope list_service_edge_router_policy_edge_routers(id)
List the edge routers that a service edge router policy applies to

List the edge routers that a service edge router policy applies to

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListEdgeRoutersEnvelope**](listEdgeRoutersEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_edge_router_policy_services

> models::ListServicesEnvelope list_service_edge_router_policy_services(id)
List the services that a service edge router policy applies to

List the services that a service edge router policy applies to

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


## patch_service_edge_router_policy

> models::Empty patch_service_edge_router_policy(id, policy)
Update the supplied fields on a service edge policy

Update the supplied fields on a service edge policy. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**ServiceEdgeRouterPolicyPatch**](ServiceEdgeRouterPolicyPatch.md) | A service edge router policy patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_service_edge_router_policy

> models::Empty update_service_edge_router_policy(id, policy)
Update all fields on a service edge policy

Update all fields on a service edge policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**ServiceEdgeRouterPolicyUpdate**](ServiceEdgeRouterPolicyUpdate.md) | A service edge router policy update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

