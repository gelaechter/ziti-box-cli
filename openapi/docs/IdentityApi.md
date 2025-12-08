# \IdentityApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**associate_identitys_service_configs**](IdentityApi.md#associate_identitys_service_configs) | **POST** /identities/{id}/service-configs | Associate service configs for a specific identity
[**create_identity**](IdentityApi.md#create_identity) | **POST** /identities | Create an identity resource
[**delete_identity**](IdentityApi.md#delete_identity) | **DELETE** /identities/{id} | Delete an identity
[**detail_identity**](IdentityApi.md#detail_identity) | **GET** /identities/{id} | Retrieves a single identity
[**detail_identity_type**](IdentityApi.md#detail_identity_type) | **GET** /identity-types/{id} | Retrieves a identity type
[**disable_identity**](IdentityApi.md#disable_identity) | **POST** /identities/{id}/disable | Set an identity as disabled
[**disassociate_identitys_service_configs**](IdentityApi.md#disassociate_identitys_service_configs) | **DELETE** /identities/{id}/service-configs | Remove associated service configs from a specific identity
[**enable_identity**](IdentityApi.md#enable_identity) | **POST** /identities/{id}/enable | Clears all disabled state from an identity
[**get_identity_authenticators**](IdentityApi.md#get_identity_authenticators) | **GET** /identities/{id}/authenticators | Retrieve the current authenticators of a specific identity
[**get_identity_enrollments**](IdentityApi.md#get_identity_enrollments) | **GET** /identities/{id}/enrollments | Retrieve the current enrollments of a specific identity
[**get_identity_failed_service_requests**](IdentityApi.md#get_identity_failed_service_requests) | **GET** /identities/{id}/failed-service-requests | Retrieve a list of the most recent service failure requests due to posture checks
[**get_identity_policy_advice**](IdentityApi.md#get_identity_policy_advice) | **GET** /identities/{id}/policy-advice/{serviceId} | Analyze policies relating the given identity and service
[**get_identity_posture_data**](IdentityApi.md#get_identity_posture_data) | **GET** /identities/{id}/posture-data | Retrieve the curent posture data for a specific identity.
[**list_identities**](IdentityApi.md#list_identities) | **GET** /identities | List identities
[**list_identity_edge_routers**](IdentityApi.md#list_identity_edge_routers) | **GET** /identities/{id}/edge-routers | List accessible edge-routers
[**list_identity_service_policies**](IdentityApi.md#list_identity_service_policies) | **GET** /identities/{id}/service-policies | List the service policies that affect an identity
[**list_identity_services**](IdentityApi.md#list_identity_services) | **GET** /identities/{id}/services | List accessible services
[**list_identity_types**](IdentityApi.md#list_identity_types) | **GET** /identity-types | List available identity types
[**list_identitys_edge_router_policies**](IdentityApi.md#list_identitys_edge_router_policies) | **GET** /identities/{id}/edge-router-policies | List the edge router policies that affect an identity
[**list_identitys_service_configs**](IdentityApi.md#list_identitys_service_configs) | **GET** /identities/{id}/service-configs | List the service configs associated a specific identity
[**patch_identity**](IdentityApi.md#patch_identity) | **PATCH** /identities/{id} | Update the supplied fields on an identity
[**remove_identity_mfa**](IdentityApi.md#remove_identity_mfa) | **DELETE** /identities/{id}/mfa | Remove MFA from an identitity
[**update_identity**](IdentityApi.md#update_identity) | **PUT** /identities/{id} | Update all fields on an identity
[**update_identity_tracing**](IdentityApi.md#update_identity_tracing) | **PUT** /identities/{id}/trace | Enable/disable data flow tracing for an identity



## associate_identitys_service_configs

> models::Empty associate_identitys_service_configs(id, service_configs)
Associate service configs for a specific identity

Associate service configs to a specific identity

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**service_configs** | [**Vec<models::ServiceConfigAssign>**](serviceConfigAssign.md) | A service config patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## create_identity

> models::CreateEnvelope create_identity(identity)
Create an identity resource

Create an identity resource. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**identity** | [**IdentityCreate**](IdentityCreate.md) | An identity to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_identity

> models::Empty delete_identity(id)
Delete an identity

Delete an identity by id. Requires admin access.

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


## detail_identity

> models::DetailIdentityEnvelope detail_identity(id)
Retrieves a single identity

Retrieves a single identity by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailIdentityEnvelope**](detailIdentityEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## detail_identity_type

> models::DetailIdentityTypeEnvelope detail_identity_type(id)
Retrieves a identity type

Retrieves a single identity type by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailIdentityTypeEnvelope**](detailIdentityTypeEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## disable_identity

> models::Empty disable_identity(id, disable)
Set an identity as disabled

Reject an identity's API session requests for N minutes or indefinitely if 0. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**disable** | [**DisableParams**](DisableParams.md) | Disable parameters | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## disassociate_identitys_service_configs

> models::Empty disassociate_identitys_service_configs(id, service_config_id_pairs)
Remove associated service configs from a specific identity

Remove service configs from a specific identity

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**service_config_id_pairs** | Option<[**Vec<models::ServiceConfigAssign>**](serviceConfigAssign.md)> | An array of service and config id pairs to remove |  |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## enable_identity

> models::Empty enable_identity(id)
Clears all disabled state from an identity

Allows an admin to remove disabled statuses from an identity. 

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


## get_identity_authenticators

> models::ListAuthenticatorsEnvelope get_identity_authenticators(id)
Retrieve the current authenticators of a specific identity

Returns a list of authenticators associated to the identity specified 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListAuthenticatorsEnvelope**](listAuthenticatorsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_identity_enrollments

> models::ListEnrollmentsEnvelope get_identity_enrollments(id)
Retrieve the current enrollments of a specific identity

Returns a list of enrollments associated to the identity specified 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListEnrollmentsEnvelope**](listEnrollmentsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_identity_failed_service_requests

> models::FailedServiceRequestEnvelope get_identity_failed_service_requests(id)
Retrieve a list of the most recent service failure requests due to posture checks

Returns a list of service session requests that failed due to posture checks. The entries will contain every policy that was verified against and every failed check in each policy. Each check will include the historical posture data and posture check configuration. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::FailedServiceRequestEnvelope**](failedServiceRequestEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_identity_policy_advice

> models::GetIdentityPolicyAdviceEnvelope get_identity_policy_advice(id, service_id)
Analyze policies relating the given identity and service

Analyzes policies to see if the given identity should be able to dial or bind the given service. | Will check services policies to see if the identity can access the service. Will check edge router policies | to check if the identity and service have access to common edge routers so that a connnection can be made. | Will also check if at least one edge router is on-line. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**service_id** | **String** | The id of a service | [required] |

### Return type

[**models::GetIdentityPolicyAdviceEnvelope**](getIdentityPolicyAdviceEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_identity_posture_data

> models::PostureDataEnvelope get_identity_posture_data(id)
Retrieve the curent posture data for a specific identity.

Returns a nested map data represeting the posture data of the identity. This data should be considered volatile. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::PostureDataEnvelope**](postureDataEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_identities

> models::ListIdentitiesEnvelope list_identities(limit, offset, filter, role_filter, role_semantic)
List identities

Retrieves a list of identity resources; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |
**role_filter** | Option<[**Vec<String>**](String.md)> |  |  |
**role_semantic** | Option<**String**> |  |  |

### Return type

[**models::ListIdentitiesEnvelope**](listIdentitiesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_identity_edge_routers

> models::ListEdgeRoutersEnvelope list_identity_edge_routers(id)
List accessible edge-routers

Retrieves a list of edge-routers that the given identity may use to access services. Supports filtering, sorting, and pagination. Requires admin access. 

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


## list_identity_service_policies

> models::ListServicePoliciesEnvelope list_identity_service_policies(id)
List the service policies that affect an identity

Retrieves a list of service policies that apply to the specified identity.

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


## list_identity_services

> models::ListServicesEnvelope list_identity_services(id, filter, policy_type)
List accessible services

Retrieves a list of services that the given identity has access to. Supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**filter** | Option<**String**> |  |  |
**policy_type** | Option<**String**> |  |  |

### Return type

[**models::ListServicesEnvelope**](listServicesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_identity_types

> models::ListIdentityTypesEnvelope list_identity_types(limit, offset, filter)
List available identity types

Retrieves a list of identity types; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListIdentityTypesEnvelope**](listIdentityTypesEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_identitys_edge_router_policies

> models::ListEdgeRouterPoliciesEnvelope list_identitys_edge_router_policies(id)
List the edge router policies that affect an identity

Retrieves a list of edge router policies that apply to the specified identity.

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


## list_identitys_service_configs

> models::ListServiceConfigsEnvelope list_identitys_service_configs(id)
List the service configs associated a specific identity

Retrieves a list of service configs associated to a specific identity

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::ListServiceConfigsEnvelope**](listServiceConfigsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_identity

> models::Empty patch_identity(id, identity)
Update the supplied fields on an identity

Update the supplied fields on an identity. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**identity** | [**IdentityPatch**](IdentityPatch.md) | An identity patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## remove_identity_mfa

> models::Empty remove_identity_mfa(id)
Remove MFA from an identitity

Allows an admin to remove MFA enrollment from a specific identity. Requires admin. 

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


## update_identity

> models::Empty update_identity(id, identity)
Update all fields on an identity

Update all fields on an identity by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**identity** | [**IdentityUpdate**](IdentityUpdate.md) | An identity update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_identity_tracing

> models::TraceDetailEnvelope update_identity_tracing(id, trace_spec)
Enable/disable data flow tracing for an identity

Allows an admin to enable/disable data flow tracing for an identity 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**trace_spec** | [**TraceSpec**](TraceSpec.md) | A traceSpec object | [required] |

### Return type

[**models::TraceDetailEnvelope**](traceDetailEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

