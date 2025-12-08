# \EnrollmentApi

All URIs are relative to *https://demo.ziti.dev/edge/management/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**create_enrollment**](EnrollmentApi.md#create_enrollment) | **POST** /enrollments | Create an outstanding enrollment for an identity
[**delete_enrollment**](EnrollmentApi.md#delete_enrollment) | **DELETE** /enrollments/{id} | Delete an outstanding enrollment
[**detail_enrollment**](EnrollmentApi.md#detail_enrollment) | **GET** /enrollments/{id} | Retrieves an outstanding enrollment
[**list_enrollments**](EnrollmentApi.md#list_enrollments) | **GET** /enrollments | List outstanding enrollments
[**list_network_jwts**](EnrollmentApi.md#list_network_jwts) | **GET** /network-jwts | Returns a list of JWTs suitable for bootstrapping network trust.
[**refresh_enrollment**](EnrollmentApi.md#refresh_enrollment) | **POST** /enrollments/{id}/refresh | Refreshes an enrollment record's expiration window



## create_enrollment

> models::CreateEnvelope create_enrollment(enrollment)
Create an outstanding enrollment for an identity

Creates a new OTT, OTTCA, or UPDB enrollment for a specific identity. If an enrollment of the same type is already outstanding the request will fail with a 409 conflict. If desired, an existing enrollment can be refreshed by `enrollments/:id/refresh` or deleted.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**enrollment** | [**EnrollmentCreate**](EnrollmentCreate.md) | An enrollment to create | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## delete_enrollment

> models::Empty delete_enrollment(id)
Delete an outstanding enrollment

Delete an outstanding enrollment by id. Requires admin access.

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


## detail_enrollment

> models::DetailEnrollmentEnvelope detail_enrollment(id)
Retrieves an outstanding enrollment

Retrieves a single outstanding enrollment by id. Requires admin access.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |

### Return type

[**models::DetailEnrollmentEnvelope**](detailEnrollmentEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_enrollments

> models::ListEnrollmentsEnvelope list_enrollments(limit, offset, filter)
List outstanding enrollments

Retrieves a list of outstanding enrollments; supports filtering, sorting, and pagination. Requires admin access. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limit** | Option<**i32**> |  |  |
**offset** | Option<**i32**> |  |  |
**filter** | Option<**String**> |  |  |

### Return type

[**models::ListEnrollmentsEnvelope**](listEnrollmentsEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## list_network_jwts

> models::ListNetworkJwtsEnvelope list_network_jwts()
Returns a list of JWTs suitable for bootstrapping network trust.

Returns a list of JWTs for trusting a network

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::ListNetworkJwtsEnvelope**](listNetworkJWTsEnvelope.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## refresh_enrollment

> models::CreateEnvelope refresh_enrollment(id, refresh)
Refreshes an enrollment record's expiration window

For expired or unexpired enrollments, reset the expiration window. A new JWT will be generated and must be used for the enrollment.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**id** | **String** | The id of the requested resource | [required] |
**refresh** | [**EnrollmentRefresh**](EnrollmentRefresh.md) | An enrollment refresh request | [required] |

### Return type

[**models::CreateEnvelope**](createEnvelope.md)

### Authorization

[ztSession](../README.md#ztSession), [oauth2](../README.md#oauth2)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

