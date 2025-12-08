# \ServicePolicyApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_service_policy**](ServicePolicyApi.md#create_service_policy) | **POST** /service-policies | Create a service policy resource
[**delete_service_policy**](ServicePolicyApi.md#delete_service_policy) | **DELETE** /service-policies/{id} | Delete a service policy
[**detail_service_policy**](ServicePolicyApi.md#detail_service_policy) | **GET** /service-policies/{id} | Retrieves a single service policy
[**list_service_policies**](ServicePolicyApi.md#list_service_policies) | **GET** /service-policies | List service policies
[**list_service_policy_identities**](ServicePolicyApi.md#list_service_policy_identities) | **GET** /service-policies/{id}/identities | List identities a service policy affects
[**list_service_policy_posture_checks**](ServicePolicyApi.md#list_service_policy_posture_checks) | **GET** /service-policies/{id}/posture-checks | List posture check a service policy includes
[**list_service_policy_services**](ServicePolicyApi.md#list_service_policy_services) | **GET** /service-policies/{id}/services | List services a service policy affects
[**patch_service_policy**](ServicePolicyApi.md#patch_service_policy) | **PATCH** /service-policies/{id} | Update the supplied fields on a service policy
[**update_service_policy**](ServicePolicyApi.md#update_service_policy) | **PUT** /service-policies/{id} | Update all fields on a service policy



## create_service_policy

> models::CreateEnvelope create_service_policy(policy)
Create a service policy resource

Create a service policy resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**policy** | [**ServicePolicyCreate**](ServicePolicyCreate.md) | A service policy to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_service_policy

> models::Empty delete_service_policy(id)
Delete a service policy

Delete a service policy by id. Requires admin access.

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


## detail_service_policy

> models::DetailServicePolicyEnvelop detail_service_policy(id)
Retrieves a single service policy

Retrieves a single service policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailServicePolicyEnvelop**](detailServicePolicyEnvelop.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_policies

> models::ListServicePoliciesEnvelope list_service_policies(limit, offset, filter)
List service policies

Retrieves a list of service policy resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListServicePoliciesEnvelope**](listServicePoliciesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_policy_identities

> models::ListIdentitiesEnvelope list_service_policy_identities(id, limit, offset, filter)
List identities a service policy affects

Retrieves a list of identity resources that are affected by a service policy; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListIdentitiesEnvelope**](listIdentitiesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_policy_posture_checks

> models::ListPostureCheckEnvelope list_service_policy_posture_checks(id, limit, offset, filter)
List posture check a service policy includes

Retrieves a list of posture check resources that are affected by a service policy; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListPostureCheckEnvelope**](listPostureCheckEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_service_policy_services

> models::ListServicesEnvelope list_service_policy_services(id, limit, offset, filter)
List services a service policy affects

Retrieves a list of service resources that are affected by a service policy; supports filtering, sorting, and pagination. Requires admin access. 

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


## patch_service_policy

> models::Empty patch_service_policy(id, policy)
Update the supplied fields on a service policy

Update the supplied fields on a service policy. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**ServicePolicyPatch**](ServicePolicyPatch.md) | A service policy patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_service_policy

> models::Empty update_service_policy(id, policy)
Update all fields on a service policy

Update all fields on a service policy by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**policy** | [**ServicePolicyUpdate**](ServicePolicyUpdate.md) | A service policy update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

