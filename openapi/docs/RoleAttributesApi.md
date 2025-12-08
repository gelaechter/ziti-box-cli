# \RoleAttributesApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**list_edge_router_role_attributes**](RoleAttributesApi.md#list_edge_router_role_attributes) | **GET** /edge-router-role-attributes | List role attributes in use by edge routers
[**list_identity_role_attributes**](RoleAttributesApi.md#list_identity_role_attributes) | **GET** /identity-role-attributes | List role attributes in use by identities
[**list_posture_check_role_attributes**](RoleAttributesApi.md#list_posture_check_role_attributes) | **GET** /posture-check-role-attributes | List role attributes in use by posture checks
[**list_service_role_attributes**](RoleAttributesApi.md#list_service_role_attributes) | **GET** /service-role-attributes | List role attributes in use by services



## list_edge_router_role_attributes

> models::ListRoleAttributesEnvelope list_edge_router_role_attributes(limit, offset, filter)
List role attributes in use by edge routers

Retrieves a list of role attributes in use by edge routers; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoleAttributesEnvelope**](listRoleAttributesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_identity_role_attributes

> models::ListRoleAttributesEnvelope list_identity_role_attributes(limit, offset, filter)
List role attributes in use by identities

Retrieves a list of role attributes in use by identities; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoleAttributesEnvelope**](listRoleAttributesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_posture_check_role_attributes

> models::ListRoleAttributesEnvelope list_posture_check_role_attributes(limit, offset, filter)
List role attributes in use by posture checks

Retrieves a list of role attributes in use by posture checks; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoleAttributesEnvelope**](listRoleAttributesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_role_attributes

> models::ListRoleAttributesEnvelope list_service_role_attributes(limit, offset, filter)
List role attributes in use by services

Retrieves a list of role attributes in use by services; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListRoleAttributesEnvelope**](listRoleAttributesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

