# \ExternalJwtSignerApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_external_jwt_signer**](ExternalJwtSignerApi.md#create_external_jwt_signer) | **POST** /external-jwt-signers | Creates an External JWT Signer
[**delete_external_jwt_signer**](ExternalJwtSignerApi.md#delete_external_jwt_signer) | **DELETE** /external-jwt-signers/{id} | Delete an External JWT Signer
[**detail_external_jwt_signer**](ExternalJwtSignerApi.md#detail_external_jwt_signer) | **GET** /external-jwt-signers/{id} | Retrieves a single External JWT Signer
[**list_external_jwt_signers**](ExternalJwtSignerApi.md#list_external_jwt_signers) | **GET** /external-jwt-signers | List External JWT Signers
[**patch_external_jwt_signer**](ExternalJwtSignerApi.md#patch_external_jwt_signer) | **PATCH** /external-jwt-signers/{id} | Update the supplied fields on an External JWT Signer
[**update_external_jwt_signer**](ExternalJwtSignerApi.md#update_external_jwt_signer) | **PUT** /external-jwt-signers/{id} | Update all fields on an External JWT Signer



## create_external_jwt_signer

> models::CreateEnvelope create_external_jwt_signer(external_jwt_signer)
Creates an External JWT Signer

Creates an External JWT Signer. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**external_jwt_signer** | [**ExternalJwtSignerCreate**](ExternalJwtSignerCreate.md) | An External JWT Signer to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_external_jwt_signer

> models::Empty delete_external_jwt_signer(id)
Delete an External JWT Signer

Delete an External JWT Signer by id. Requires admin access. 

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


## detail_external_jwt_signer

> models::DetailExternalJwtSignerEnvelope detail_external_jwt_signer(id)
Retrieves a single External JWT Signer

Retrieves a single External JWT Signer by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailExternalJwtSignerEnvelope**](detailExternalJwtSignerEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_external_jwt_signers

> models::ListExternalJwtSignersEnvelope list_external_jwt_signers(limit, offset, filter)
List External JWT Signers

Retrieves a list of external JWT signers for authentication

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListExternalJwtSignersEnvelope**](listExternalJwtSignersEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_external_jwt_signer

> models::Empty patch_external_jwt_signer(id, external_jwt_signer)
Update the supplied fields on an External JWT Signer

Update only the supplied fields on an External JWT Signer by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**external_jwt_signer** | [**ExternalJwtSignerPatch**](ExternalJwtSignerPatch.md) | An External JWT Signer patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_external_jwt_signer

> models::Empty update_external_jwt_signer(id, external_jwt_signer)
Update all fields on an External JWT Signer

Update all fields on an External JWT Signer by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**external_jwt_signer** | [**ExternalJwtSignerUpdate**](ExternalJwtSignerUpdate.md) | An External JWT Signer update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

