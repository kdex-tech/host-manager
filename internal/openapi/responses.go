/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openapi

// Component references for the shared responses declared once in the
// generated document and pointed at from every operation that can return
// them. They are named because they are INTERNAL cross-references: a typo
// produces a document that still serializes and still validates as JSON,
// but whose $ref resolves to nothing -- a failure that surfaces in a
// client generator long after the change that caused it. The most-used of
// them appears at 25 call sites.
const (
	RespRefBadRequest          = "#/components/responses/BadRequest"
	RespRefFound               = "#/components/responses/Found"
	RespRefInternalServerError = "#/components/responses/InternalServerError"
	RespRefNotFound            = "#/components/responses/NotFound"
	RespRefSeeOther            = "#/components/responses/SeeOther"
	RespRefUnauthorized        = "#/components/responses/Unauthorized"
)
