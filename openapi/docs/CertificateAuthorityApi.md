# \CertificateAuthorityApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_ca**](CertificateAuthorityApi.md#create_ca) | **POST** /cas | Creates a CA
[**delete_ca**](CertificateAuthorityApi.md#delete_ca) | **DELETE** /cas/{id} | Delete a CA
[**detail_ca**](CertificateAuthorityApi.md#detail_ca) | **GET** /cas/{id} | Retrieves a single CA
[**get_ca_jwt**](CertificateAuthorityApi.md#get_ca_jwt) | **GET** /cas/{id}/jwt | Retrieve the enrollment JWT for a CA
[**list_cas**](CertificateAuthorityApi.md#list_cas) | **GET** /cas | List CAs
[**patch_ca**](CertificateAuthorityApi.md#patch_ca) | **PATCH** /cas/{id} | Update the supplied fields on a CA
[**update_ca**](CertificateAuthorityApi.md#update_ca) | **PUT** /cas/{id} | Update all fields on a CA
[**verify_ca**](CertificateAuthorityApi.md#verify_ca) | **POST** /cas/{id}/verify | Verify a CA



## create_ca

> models::CreateEnvelope create_ca(ca)
Creates a CA

Creates a CA in an unverified state. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**ca** | [**CaCreate**](CaCreate.md) | A CA to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_ca

> models::Empty delete_ca(id)
Delete a CA

Delete a CA by id. Deleting a CA will delete its associated certificate authenticators. This can make it impossible for identities to authenticate if they no longer have any valid authenticators. Requires admin access. 

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


## detail_ca

> models::DetailCaEnvelope detail_ca(id)
Retrieves a single CA

Retrieves a single CA by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailCaEnvelope**](detailCaEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_ca_jwt

> String get_ca_jwt(id)
Retrieve the enrollment JWT for a CA

For CA auto enrollment, the enrollment JWT is static and provided on each CA resource. This endpoint provides the jwt as a text response. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

**String**

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/jwt, application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_cas

> models::ListCasEnvelope list_cas(limit, offset, filter)
List CAs

Retrieves a list of CA resources; supports filtering, sorting, and pagination. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListCasEnvelope**](listCasEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## patch_ca

> models::Empty patch_ca(id, ca)
Update the supplied fields on a CA

Update only the supplied fields on a CA by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**ca** | [**CaPatch**](CaPatch.md) | A CA patch object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## update_ca

> models::Empty update_ca(id, ca)
Update all fields on a CA

Update all fields on a CA by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**ca** | [**CaUpdate**](CaUpdate.md) | A CA update object | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## verify_ca

> models::Empty verify_ca(id, certificate)
Verify a CA

Allows a CA to become verified by submitting a certificate in PEM format that has been signed by the target CA. The common name on the certificate must match the verificationToken property of the CA. Unverfieid CAs can not be used for enrollment/authentication. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**certificate** | **String** | A PEM formatted certificate signed by the target CA with the common name matching the CA's validationToken | [required] |

### Return type

[**models::Empty**](empty.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: text/plain
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

