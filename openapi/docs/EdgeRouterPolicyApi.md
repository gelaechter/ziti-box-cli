# \EdgeRouterPolicyApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_edge_router_policy**](EdgeRouterPolicyApi.md#create_edge_router_policy) | **POST** /edge-router-policies | Create an edge router policy resource
[**delete_edge_router_policy**](EdgeRouterPolicyApi.md#delete_edge_router_policy) | **DELETE** /edge-router-policies/{id} | Delete an edge router policy
[**detail_edge_router_policy**](EdgeRouterPolicyApi.md#detail_edge_router_policy) | **GET** /edge-router-policies/{id} | Retrieves a single edge router policy
[**list_edge_router_policies**](EdgeRouterPolicyApi.md#list_edge_router_policies) | **GET** /edge-router-policies | List edge router policies
[**list_edge_router_policy_edge_routers**](EdgeRouterPolicyApi.md#list_edge_router_policy_edge_routers) | **GET** /edge-router-policies/{id}/edge-routers | List edge routers a policy affects
[**list_edge_router_policy_identities**](EdgeRouterPolicyApi.md#list_edge_router_policy_identities) | **GET** /edge-router-policies/{id}/identities | List identities an edge router policy affects
[**patch_edge_router_policy**](EdgeRouterPolicyApi.md#patch_edge_router_policy) | **PATCH** /edge-router-policies/{id} | Update the supplied fields on an edge router policy
[**update_edge_router_policy**](EdgeRouterPolicyApi.md#update_edge_router_policy) | **PUT** /edge-router-policies/{id} | Update all fields on an edge router policy



## create_edge_router_policy

> models::CreateEnvelope create_edge_router_policy(policy)
Create an edge router policy resource

Create an edge router policy resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**policy** | [**EdgeRouterPolicyCreate**](EdgeRouterPolicyCreate.md) | An edge router policy to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_edge_router_policy

> models::Empty delete_edge_router_policy(id)
Delete an edge router policy

Delete an edge router policy by id. Requires admin access.

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


## detail_edge_router_policy

> models::DetailEdgeRouterPolicyEnvelope detail_edge_router_policy(id)
Retrieves a single edge router policy

Retrieves a single edge router policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailEdgeRouterPolicyEnvelope**](detailEdgeRouterPolicyEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_policies

> models::ListEdgeRouterPoliciesEnvelope list_edge_router_policies(limit, offset, filter)
List edge router policies

Retrieves a list of edge router policy resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListEdgeRouterPoliciesEnvelope**](listEdgeRouterPoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_edge_router_policy_edge_routers

> models::ListEdgeRoutersEnvelope list_edge_router_policy_edge_routers(id)
List edge routers a policy affects

Retrieves a list of edge routers an edge router policy resources affects; supports filtering, sorting, and pagination. Requires admin access. 

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


## list_edge_router_policy_identities

> models::ListIdentitiesEnvelope list_edge_router_policy_identities(id)
List identities an edge router policy affects

Retrieves a list of identities an edge router policy resources affects; supports filtering, sorting, and pagination. Requires admin access. 

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


## patch_edge_router_policy

> models::Empty patch_edge_router_policy(id, policy)
Update the supplied fields on an edge router policy

Update the supplied fields on an edge router policy. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**EdgeRouterPolicyPatch**](EdgeRouterPolicyPatch.md) | An edge router policy patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_edge_router_policy

> models::Empty update_edge_router_policy(id, policy)
Update all fields on an edge router policy

Update all fields on an edge router policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**EdgeRouterPolicyUpdate**](EdgeRouterPolicyUpdate.md) | An edge router policy update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

