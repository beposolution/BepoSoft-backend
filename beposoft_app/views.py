from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
import jwt
import requests
import logging
import itertools
from .serializers import *
from .models import User
from django.contrib.auth.hashers import check_password, make_password
from datetime import datetime, timedelta, time, date
from django.db.models import Q, Prefetch, Value
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.contrib.auth import authenticate
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError, transaction
from decimal import Decimal, InvalidOperation
from django.db.models import Sum
from django.http import Http404, JsonResponse
from django.utils.dateparse import parse_date
from django.db.models import Count, Q
from collections import defaultdict
from rest_framework.parsers import MultiPartParser, FormParser
import pandas as pd
import os
from django.utils import timezone
from django.shortcuts import render
from rest_framework.pagination import PageNumberPagination
from bepocart.models import *
from django.core.files.base import ContentFile
from django.db.models.functions import Coalesce
from django.db.models import Sum, F, DecimalField, ExpressionWrapper
from django.db.models.functions import Cast, NullIf
from django.db.models.functions import TruncDate
import calendar
from django.utils.timezone import localtime

logger = logging.getLogger(__name__)


class StandardPagination(PageNumberPagination):
    page_size = 50

class UserRegistrationAPIView(APIView):
    def post(self, request):
        try:
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "status": "success",
                    "message": "Registration successfully completed",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "status": "error",
                    "message": "Registration failed",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
class TokenLoginAPIView(APIView):
    def post(self, request, token):
        try:
            # Decode the JWT token
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            user_id = payload.get('id')
            user = User.objects.filter(id=user_id).first()

            if not user:
                return Response({"status": "error", "message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            # Optional: you can authenticate session, return user data, etc.
            return Response({
                "status": "success",
                "message": "Token is valid",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "name": user.name,
                    "department": user.department_id.name if user.department_id else None,
                }
            }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError:
            return Response({"status": "error", "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)

        except jwt.InvalidTokenError:
            return Response({"status": "error", "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   

class UserLoginAPIView(APIView):
    def post(self, request):
        try:
            serializer = UserLoginSerializer(data=request.data)
            if serializer.is_valid():
                # username and password from serializer for login
                username = serializer.validated_data.get('username')
                password = serializer.validated_data.get('password')

                customer = User.objects.filter(username=username, approval_status="approved").first()

                if customer and customer.check_password(password):
                    if customer.designation == "HR":
                        self.handle()

                    expiration_time = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)

                    user_token = {
                        'id': customer.pk,
                        'username': customer.username,
                        'name': customer.name,
                        'exp': expiration_time,
                        "active": customer.department_id.name,
                        'iat': datetime.utcnow(),
                    }

                    token = jwt.encode(user_token, settings.SECRET_KEY, algorithm='HS256')
                    response_data = {
                        "status": "success",
                        "message": "Login successful",
                        'id': customer.pk,
                        "token": token,
                        'name': customer.name,
                        "active": customer.department_id.name
                    }

                    warehouse = getattr(customer, 'warehouse_id', None)
                    if warehouse:
                        response_data['warehouse_id'] = warehouse.id

                    response = Response(response_data, status=status.HTTP_200_OK)

                    response.set_cookie(
                        key='token',
                        value=token,
                        httponly=True,
                        samesite='Lax',
                        secure=settings.SECURE_COOKIE
                    )
                    return response
                else:
                    return Response({
                        "status": "error",
                        "message": "Invalid username or password"
                    }, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({
                    "status": "error",
                    "message": "Invalid data",
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    
    
    def handle(self, *args, **kwargs):
        today = now().date()
        staff_members = User.objects.all()
 
        for staff in staff_members:
            # Create attendance for staff if it doesn't exist for today
            Attendance.objects.get_or_create(staff=staff, date=today, defaults={"attendance_status": "Present"})
      

class BaseTokenView(APIView):
    
    def get_user_from_token(self, request):
        token = request.headers.get('Authorization')
        
        if not token:
            return None, Response({"status": "Unauthorized", "message": "No token provided"}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not token.startswith("Bearer "):
            return None, Response({"status": "error", "message": "Token must start with 'Bearer '"}, status=status.HTTP_401_UNAUTHORIZED)
        
        token = token.split(" ")[1]

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('id')
            user = User.objects.filter(pk=user_id, approval_status="approved").first()

            if not user:
                return None, Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            return user, None
        
        except jwt.ExpiredSignatureError:
            return None, Response({"status": "error", "message": "Token has expired"}, status=status.HTTP_401_UNAUTHORIZED)
        
        except jwt.InvalidTokenError:
            return None, Response({"status": "error", "message": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)
        
        except Exception as e:
            return None, Response({"status": "error", "message": "An error occurred while decoding the token", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
      
        

class UserProfileData(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = UserSerializer(user)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"status": "error", "message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            logger.exception("An error occurred in UserProfileData: %s", str(e))
            return Response({"status": "error", "message": "An internal error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# API for flutter
class CreateUser2View(BaseTokenView):
    def post(self, request):
        try:
            # Validate user from token
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response


            # Validate and process allocated_states
            allocated_states = request.data.get('allocated_states')
            warehouse_id = request.data.get('warehouse_id')

            
            # Save user data
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user_instance = serializer.save()


                if allocated_states:
                    valid_states = State.objects.filter(pk__in=allocated_states)
                    user_instance.allocated_states.set(valid_states)
                if warehouse_id:
                    try:
                        warehouse = WareHouse.objects.get(pk=warehouse_id)
                        user_instance.warehouse_id = warehouse
                        user_instance.save()
                    except WareHouse.DoesNotExist:
                        return Response(
                            {
                                "status": "error",
                                "message": "Invalid warehouse_id provided"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
    
                    user_instance.save()

                response_serializer = UserSerializer(user_instance)

                return Response(
                    {
                        "data": serializer.data,
                        "message": "User created successfully"
                    },
                    status=status.HTTP_201_CREATED
                )
                
            return Response({"status": "error","message": "Validation failed","errors": serializer.errors},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# API for react
class CreateUserView(BaseTokenView):
    def post(self, request):
        try:
            # Validate user from token
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response


            # Validate and process allocated_states
            allocated_states = request.data.getlist('allocated_states')
            warehouse_id = request.data.get('warehouse_id')

            
            # Save user data
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user_instance = serializer.save()


                if allocated_states:
                    valid_states = State.objects.filter(pk__in=allocated_states)
                    user_instance.allocated_states.set(valid_states)
                if warehouse_id:
                    try:
                        warehouse = WareHouse.objects.get(pk=warehouse_id)
                        user_instance.warehouse_id = warehouse
                        user_instance.save()
                    except WareHouse.DoesNotExist:
                        return Response(
                            {
                                "status": "error",
                                "message": "Invalid warehouse_id provided"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
    
                    user_instance.save()

                response_serializer = UserSerializer(user_instance)

                return Response(
                    {
                        "data": serializer.data,
                        "message": "User created successfully"
                    },
                    status=status.HTTP_201_CREATED
                )
                
            return Response({"status": "error","message": "Validation failed","errors": serializer.errors},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class Users(BaseTokenView):
    def get(self, request):
        try:
            # user, error_response = self.get_user_from_token(request)
            # if error_response:
            #     return error_response

                        
            users = User.objects.all()
            serializer = UserUpdateSerilizers(users, many=True)
           
            
            return Response({
                "data": serializer.data,
                "message": "Users fetching is successfully completed"
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({"status": "error", "message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            return Response({
                "message": "An error occurred while fetching users",
                "error": str(e)  
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class UsersByFamilyView(BaseTokenView):
    def get(self, request, family_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            users = User.objects.filter(
                family_id=family_id
            ).select_related(
                'family',
                'supervisor_id',
                'department_id',
                'warehouse_id',
                'country_code'
            ).prefetch_related(
                'allocated_states'
            ).order_by('-id')

            if not users.exists():
                return Response(
                    {
                        "status": "error",
                        "message": "No users found for this family id"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = UserUpdateSerilizers(users, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "Users fetched successfully",
                    "family_id": family_id,
                    "count": users.count(),
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching users by family id",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        

class StaffOrders(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            status_filter = request.GET.get("status", "").strip()

            orders = Order.objects.filter(
                manage_staff=user.pk
            )

            if search:
                orders = orders.filter(
                    Q(invoice__icontains=search) |
                    Q(customer__name__icontains=search) 
                )

            if status_filter and status_filter.lower() != "all status":
                orders = orders.filter(status__iexact=status_filter)

            orders = orders.order_by('-id')

            paginator = StandardPagination()
            page = paginator.paginate_queryset(orders, request)

            serializer = OrderModelSerilizer(page, many=True)

            return paginator.get_paginated_response({
                "message": "Orders fetched successfully",
                "data": serializer.data
            })

        except Exception as e:
            return Response({
                "message": "An error occurred while fetching orders",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

class OrderImageUploadView(BaseTokenView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        order_id = request.data.get('order')
        images = request.FILES.getlist('images')

        if not order_id:
            return Response({"status": "error", "message": "Order ID is required."}, status=400)
        if not images:
            return Response({"status": "error", "message": "No images uploaded."}, status=400)

        try:
            order = Order.objects.get(pk=order_id)
        except Order.DoesNotExist:
            return Response({"status": "error", "message": "Order not found."}, status=404)

        saved_images = []
        for img in images:
            instance = OrderImage(order=order, image=img)
            instance.save()
            saved_images.append(instance)

        serializer = OrderImageSerializer(saved_images, many=True)
        return Response({"message": "Images uploaded successfully", "data": serializer.data}, status=201)

class OrderImageView(BaseTokenView):
    def get(self, request, order_id):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            order = Order.objects.get(pk=order_id)
        except Order.DoesNotExist:
            return Response({"status": "error", "message": "Order not found."}, status=404)

        images = OrderImage.objects.filter(order=order)
        image_serializer = OrderImageSerializer(images, many=True)

        return Response({
            "order": order.id,
            "invoice": order.invoice,
            "images": image_serializer.data
        }, status=200)
        

class DeleteOrderImageView(BaseTokenView):
    def delete(self, request, image_id):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            image = OrderImage.objects.get(pk=image_id)
            image.image.delete(save=False)  # Deletes the file from storage
            image.delete()  # Deletes the database record
            return Response({"status": "success", "message": "Image deleted successfully."}, status=200)
        except OrderImage.DoesNotExist:
            return Response({"status": "error", "message": "Image not found."}, status=404)
        

class OrderPaymentImageUploadView(BaseTokenView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        order_id = request.data.get('order')
        images = request.FILES.getlist('images')

        if not order_id:
            return Response({"status": "error", "message": "Order ID is required."}, status=400)
        if not images:
            return Response({"status": "error", "message": "No images uploaded."}, status=400)

        try:
            order = Order.objects.get(pk=order_id)
        except Order.DoesNotExist:
            return Response({"status": "error", "message": "Order not found."}, status=404)

        saved_images = []
        for img in images:
            instance = OrderPaymentImages(order=order, image=img)
            instance.save()
            saved_images.append(instance)

        serializer = OrderPaymentImagesSerializer(saved_images, many=True)
        return Response({"message": "Images uploaded successfully", "data": serializer.data}, status=201)

class OrderPaymentImageView(BaseTokenView):
    def get(self, request, order_id):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            order = Order.objects.get(pk=order_id)
        except Order.DoesNotExist:
            return Response({"status": "error", "message": "Order not found."}, status=404)

        images = OrderPaymentImages.objects.filter(order=order)
        image_serializer = OrderPaymentImagesSerializer(images, many=True)

        return Response({
            "order": order.id,
            "invoice": order.invoice,
            "images": image_serializer.data
        }, status=200)
        

class DeleteOrderPaymentImageView(BaseTokenView):
    def delete(self, request, image_id):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            image = OrderPaymentImages.objects.get(pk=image_id)
            image.image.delete(save=False)  # Deletes the file from storage
            image.delete()  # Deletes the database record
            return Response({"status": "success", "message": "Image deleted successfully."}, status=200)
        except OrderPaymentImages.DoesNotExist:
            return Response({"status": "error", "message": "Image not found."}, status=404)
        

class UserDataUpdate(BaseTokenView):
    def get_user(self, pk):
        return get_object_or_404(User, pk=pk)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            user = self.get_user(pk)
            
            serializer = UserSerializer(user)
            return Response({"message": "User fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            # Authenticate the user using a token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Retrieve the user object to be updated
            user = self.get_user(pk)
            

          # If the password is provided in the request, hash it
            
            if 'password' in request.data:
                request.data['password'] = make_password(request.data['password'])
                

            # Use partial=True to allow partial updates
            serializer = UserUpdateSerilizers(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
             
                return Response(
                    {"message": "User updated successfully", "data": serializer.data},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "message": "Validation error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class UserCustomerAddingView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            
            serializer = CustomerModelSerializer(data=request.data)
            if serializer.is_valid():
                customer = serializer.save()
                
                Shipping.objects.create(
                    created_user=authUser,
                    customer=customer,
                    name=customer.name,
                    address=customer.address or "",
                    zipcode=customer.zip_code or "",
                    city=customer.city or "",
                    state=customer.state,
                    country="India",  # Default, or get from request if needed
                    phone=customer.phone,
                    email=customer.email or "",
                )
                return Response({"data": serializer.data, "message": "Customer added successfully"}, status=status.HTTP_201_CREATED)
            return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"status": "error", "message": "An internal server error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CustomerTypeView(BaseTokenView):
    def get(self, request, pk=None):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        if pk is not None:
            obj = get_object_or_404(CustomerType, pk=pk)
            ser = CustomerTypeSerializer(obj)
            return Response(ser.data, status=status.HTTP_200_OK)

        qs = CustomerType.objects.all().order_by("id")
        ser = CustomerTypeSerializer(qs, many=True)
        return Response(ser.data, status=status.HTTP_200_OK)

    def post(self, request):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        ser = CustomerTypeSerializer(data=request.data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data, status=status.HTTP_201_CREATED)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk=None):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        if pk is None:
            return Response({"detail": "ID is required for PUT."}, status=status.HTTP_400_BAD_REQUEST)

        obj = get_object_or_404(CustomerType, pk=pk)
        ser = CustomerTypeSerializer(obj, data=request.data)  # full update
        if ser.is_valid():
            ser.save()
            return Response(ser.data, status=status.HTTP_200_OK)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomerView(BaseTokenView):
   
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # customers = Customers.objects.all().order_by('-created_at') 
            # serializer = CustomerModelSerializerLimited(customers, many=True)

            search = request.GET.get("search", "")

            customers = Customers.objects.select_related("manager","state","family").order_by('-created_at')

            if search:
                customers = customers.filter(
                    Q(name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(email__icontains=search)
                )

            paginator = StandardPagination()
            result_page = paginator.paginate_queryset(customers, request)

            serializer = CustomerModelSerializerLimited(result_page, many=True)

            return paginator.get_paginated_response(serializer.data)

            # return Response({"data": serializer.data, "message": "Customers retrieved successfully"}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"status": "error", "message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
class CustomerUpdateView(BaseTokenView):
    
    def get_customer(self, pk):
        return get_object_or_404(Customers, pk=pk)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            customer = self.get_customer(pk)
            serializer = CustomerSerilizers(customer)
            return Response({"data": serializer.data, "message": "Customer retrieved successfully"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            customer = Customers.objects.get(pk=pk)
        except Customers.DoesNotExist:
            return Response({"error": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = CustomerEditSerializer(customer, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FamilyCreatView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = FamilySerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Family added successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class FamilyAllView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            family = Family.objects.all()
            serializer = FamilySerializer(family, many=True)
            return Response({"message": "Family list successfully retrieved", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class FamilyUpdateView(BaseTokenView):
    
    def get_family(self, pk):
        return get_object_or_404(Family, pk=pk)
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            family = self.get_family(pk)
            serializer = FamilySerializer(family)
            return Response({"message": "Family fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            family = self.get_family(pk)
            family.delete()
            return Response({"message": "Family deleted successfully"}, status=status.HTTP_200_OK)
                        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            family = self.get_family(pk)
            serializer = FamilySerializer(family, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Family updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ProductCreateView(BaseTokenView):
    @transaction.atomic
    def post(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Extract and validate family IDs
            family_ids = request.data.get('family')
            if not family_ids:
                return Response({"message": "No family IDs provided"}, status=status.HTTP_400_BAD_REQUEST)

            families = Family.objects.filter(pk__in=family_ids)
            if families.count() != len(family_ids):
                invalid_ids = set(family_ids) - set(families.values_list('id', flat=True))
                return Response({"message": "Invalid family IDs", "invalid_ids": list(invalid_ids)}, status=status.HTTP_400_BAD_REQUEST)
                

            # Add created_user to request data
            request.data['created_user'] = authUser.pk

            # Validate and save product
            logger.info(f"Received data: {request.data}")  
            serializer = ProductsAddSerializer(data=request.data)
            if serializer.is_valid():
                product = serializer.save()
                product.family.set(families)
                
                 # Associate families with product
            return Response({"message": "Product added successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
           

        except KeyError as e:
            return Response({"message": f"Missing required field: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)






class ProductListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch all products
            products = Products.objects.all()

            # Initialize a set to track unique groupIDs
            seen_group_ids = set()
            unique_products = []

            # Iterate through products and filter out duplicates by groupID
            for product in products:
                if product.groupID not in seen_group_ids:
                    seen_group_ids.add(product.groupID)
                    unique_products.append(product)

            # Serialize the unique products list
            serializer = ProductSingleviewSerializres(unique_products, many=True)
          

            return Response({
                "message": "Product list successfully retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except authUser.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User does not exist"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class ListAllProducts(BaseTokenView):  
    def get(self, request):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            # products = Products.objects.all()

            products = Products.objects.all()

            paginator = StandardPagination()
            result_page = paginator.paginate_queryset(products, request)

            serializer = ProductSingleviewSerializres(result_page, many=True)

            return paginator.get_paginated_response(serializer.data)
            # serializer = ProductsListViewSerializers(products, many=True)
            # return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching products: {str(e)}")
            return Response({
                "error": "An error occurred while retrieving products. Please try again later."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

class ProductUpdateView(BaseTokenView):
    
    def get_product(self,pk):
        return get_object_or_404(Products, pk=pk)
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            product = self.get_product(pk)

            serializer = ProductSerializerView(product)
            return Response({"message": "Product fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            product = self.get_product(pk)
            product.delete()
            return Response({"message": "Product deleted successfully"}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            product = self.get_product(pk)

            serializer = ProductsSerializer(product, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                
                return Response({"message": "Product updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
    

              
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class SingleProductImageCreateView(BaseTokenView):
    def post(self, request, pk):
        try:
            # Get authenticated user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Get the main product
            product = get_object_or_404(Products, pk=pk)

            # Ensure the product is a variant and has a groupId and color
            if not hasattr(product, 'groupID') or not hasattr(product, 'color'):
                return Response({"message": "Invalid product type or missing attributes"}, status=status.HTTP_400_BAD_REQUEST)

            # Get all product variants in the same group and color
            related_products = Products.objects.filter(groupID=product.groupID, color=product.color)

            # Get the uploaded images
            images = request.FILES.getlist('images')
            if not images:
                return Response({"message": "No images were uploaded"}, status=status.HTTP_400_BAD_REQUEST)

            saved_images = []

            # Save images for each related productwdwdwdw
            for image in images:
                for related_product in related_products:
                    single_product = SingleProducts.objects.create(
                        product=related_product,
                        created_user=authUser,
                        image=image
                    )
                    saved_images.append({
                        "product_id": related_product.id,
                        "image_id": single_product.id
                    })

            return Response({
                "message": f"{len(saved_images)} images added successfully",
                "saved_images": saved_images
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


            

class SingleProductImageView(BaseTokenView):
    def delete(self,request,pk):
        try :
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            image = get_object_or_404(SingleProducts,pk=pk)
            image.delete()
            return Response({"message":"Image deleted successfuly completed"},status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class  ApprovedProductList(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            approved_products = Products.objects.filter(approval_status='Approved')
            serializer = ProductSingleviewSerializres(approved_products, many=True)
            
            return Response({
                "message": "Approved products fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred while fetching products",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class  DisapprovedProductList(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            approved_products = Products.objects.filter(approval_status='Disapproved')
            serializer = ProductSingleviewSerializres(approved_products, many=True)
            
            return Response({
                "message": "Approved products fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred while fetching products",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




                
class DepartmentCreateView(BaseTokenView):
    def post(self,request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = DepartmentSerilizers(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Departmen added successftully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class DepartmentListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            department = Departments.objects.all()
            serializer = DepartmentSerilizers(department, many=True)
            return Response({"message": "Departments list successfully retrieved", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    

class DepartmentsUpdateView(BaseTokenView):
    
    def get_department(self, pk):
        return get_object_or_404(Departments, pk=pk)
    
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            department = self.get_department(pk)
            serializer = DepartmentSerilizers(department)
            
            return Response({"message": "Department fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            department = self.get_department(pk)
            
            serializer = DepartmentSerilizers(department, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Department updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            department = self.get_department(pk)
            department.delete()
            return Response({"message": "Departments deleted successfully"}, status=status.HTTP_200_OK)
                                
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class StateCreateView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            data = request.data
            if isinstance(data, dict):
                data = [data]
            
            if not isinstance(data, list):
                return Response(
                    {"status": "error", "message": "Invalid data format. Must be a dictionary or list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = StateSerializers(data=data , many=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "State added successftully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class StateListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            state = State.objects.all().order_by('id')
            serializer = StateSerializers(state, many=True)
            return Response({"message": "State list successfully retrieved", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

     

class StateUpdateView(BaseTokenView):
    def get_states(self,pk):
        return get_object_or_404(State, pk=pk)
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            state = self.get_states(pk)
            serializer = StateSerializers(state)
            return Response({"message": "State fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            state = self.get_states(pk)
            state.delete()
            return Response({"message": "State deleted successfully"}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            state = self.get_states(pk)
            serializer = StateSerializers(state, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "State updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class SupervisorCreateView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = SupervisorSerializers(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Supervisor added successftully", "data": serializer.data}, status=status.HTTP_201_CREATED)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SuperviserListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
            supervisor = Supervisor.objects.all()
            serializer = SupervisorSerializerView(supervisor, many=True)
            return Response({"message": "Supervisor list successfully retrieved", "data": serializer.data}, status=status.HTTP_200_OK)
                        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        

class SupervisorUpdateView(BaseTokenView):
    def get_supervisor(self,pk):
        return get_object_or_404(Supervisor,pk=pk)
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            supervisor = self.get_supervisor(pk)
            serializer = SupervisorSerializers(supervisor)
            return Response({"message": "Supervisor fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            supervisor = self.get_supervisor(pk)

            serializer = SupervisorSerializers(supervisor, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Supervisor updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            supervisor = self.get_supervisor(pk)

            supervisor.delete()
            return Response({"message": "Supervisor deleted successfully"}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ShippingCreateView(BaseTokenView):
    
    def get_customer(self,pk):
        return get_object_or_404(Customers,pk=pk)
    
    def post(self, request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            customer = self.get_customer(pk)
            
            serializer = ShippingSerializers(data=request.data,context={'created_user':authUser}) 
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Shipping Address Add successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self, request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            customer = self.get_customer(pk)
            
            shipping = Shipping.objects.filter(customer=customer)
            serializer = ShippingAddressView(shipping, many=True)
            return Response({"message": "Shipping Address List successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ShippingDetailView(BaseTokenView):
    def get(self, request, address_id):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch the shipping address by ID
            shipping_address = Shipping.objects.get(pk=address_id)
            
            # Serialize the shipping address
            serializer = ShippingSerializers(shipping_address)

            return Response({
                "message": "Shipping address retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Shipping.DoesNotExist:
            return Response({
                "status": "error",
                "message": "Shipping address not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


            
class CustomerShippingAddressUpdate(BaseTokenView):
    def shipping_address(self,pk):
        return get_object_or_404(Shipping,pk=pk)
    
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            address = self.shipping_address(pk)
            serializer = ShippingSerializers(address)
            return Response({"message": "Address fetched successfully", "data": serializer.data}, status=status.HTTP_200_OK)
                            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request,pk):
        try:
            tauthUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            address = self.shipping_address(pk)
            address.delete()
            return Response({"message": "Customer address deleted successfully"}, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            address = self.shipping_address(pk)
            serializer = ShippingSerializers(address, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "address updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"message": "Validation error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



import json
import itertools

class VariantProductCreate(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Get request data
            product_id = request.data.get("product")
            attributes = request.data.get("attributes", "[]")

            try:
                attributes = json.loads(attributes) 
            except json.JSONDecodeError:
                return Response({"message": "Invalid attributes format"}, status=status.HTTP_400_BAD_REQUEST)

            images = request.FILES.getlist('images')
             

            # Fetch product
            product_instance = Products.objects.filter(pk=product_id).first()
            if not product_instance:
                return Response({"message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

            # Get the existing product's family
            existing_family = product_instance.family.all()  # Retrieve the product's existing family

            # Process attributes for variants
            if product_instance.type == "variant":
                attribute_values = {}
                for attr in attributes:
                    attr_name = attr.get("attribute")
                    attr_values_list = attr.get("values", [])

                    if not isinstance(attr_values_list, list):
                        return Response({"message": "Attribute values must be a list"}, status=status.HTTP_400_BAD_REQUEST)

                    attribute_values[attr_name] = attr_values_list

                combinations = list(itertools.product(*attribute_values.values()))

                for combination in combinations:
                    combined_attr = dict(zip(attribute_values.keys(), combination))

                    all_attributes = '-'.join(combination)  

                    # Create the variant name based on attributes
                    name = f"{product_instance.name}-{'-'.join(combination)}"

                    # Initialize values for color and size based on attribute names
                    color = None
                    size = None

                    # The first attribute value will be assigned to color, and the second to size
                    # Assign the first value to color
                    if combined_attr:
                        color = combination[0]  # First attribute value for color
                    # Assign the second value to size
                    if len(combination) > 1:
                        size = combination[1]  # Second attribute value for size

                    # Create the variant product with the same family
                    variant_product = Products.objects.create(
                        created_user=User.objects.get(pk=authUser.pk),
                        name=name,
                        type="variant",
                        unit=product_instance.unit,
                        purchase_rate=product_instance.purchase_rate,
                        tax=product_instance.tax,
                        exclude_price=product_instance.exclude_price,
                        selling_price=product_instance.selling_price,
                        stock=product_instance.stock,
                        color=color,
                        size=size,
                        groupID=product_instance.groupID,
                    )

                    # Add the existing family to the variant product using set()
                    variant_product.family.set(existing_family)

            else:
                # If it's not a variant, just handle the image uploads
                for image in images:
                    SingleProducts.objects.create(
                        product=product_instance,
                        created_user=User.objects.get(pk=authUser.pk),
                        image=image
                    )

            return Response({"message": "Product added successfully"}, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"An error occurred: {str(e)}", exc_info=True)
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class VariantProductsByProductView(BaseTokenView):
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            product = get_object_or_404(Products,pk=pk)
            serializer = ProductSerializerView(product)
            return Response({"products": serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

import traceback
            
# class CreateOrder(BaseTokenView):
#     @transaction.atomic
#     def post(self, request):
#         try:
#             authUser, error_response = self.get_user_from_token(request)
#             if error_response:
#                 return error_response

#             cart_items = BeposoftCart.objects.filter(user=authUser)
#             if not cart_items.exists():
#                 return Response({"status": "error", "message": " Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)

            
#             serializer = OrderSerializer(data=request.data)
#             if not serializer.is_valid():
#                 return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

#             order = serializer.save()

#             # Aggregate product quantities and other data
#             product_data = {}
#             product_ids = set()
#             for item in cart_items:
#                 product_id = item.product.pk
#                 product_ids.add(product_id)
#                 if product_id not in product_data:
#                     product_data[product_id] = {
#                         "product": item.product,
#                         "quantity": Decimal(item.quantity),
#                         "discount": Decimal(item.discount or 0),
#                         "tax": Decimal(item.product.tax or 0),
#                         "rate": Decimal(item.price or 0),
#                         "description": item.note,
#                     }
#                 else:
#                     product_data[product_id]["quantity"] += Decimal(item.quantity)
#                     product_data[product_id]["discount"] += Decimal(item.discount or 0)

            
#             for product_id, data in product_data.items():
#                 OrderItem.objects.create(
#                     order=order,
#                     product=data["product"],
#                     quantity=int(data["quantity"]),
#                     discount=data["discount"],
#                     tax=data["tax"],
#                     rate=data["rate"],
#                     description=data["description"],
#                 )


#             # Clear cart after order creation
#             cart_items.delete()
#             return Response({"status": "success", "message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

#         except Exception as e:
#             logger.error(f"Unexpected error during order creation: {e}", exc_info=True)
#             traceback.print_exc()
#             return Response({"status": "error", "message": "An unexpected error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateOrder(BaseTokenView):

    @transaction.atomic
    def post(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch cart items
            cart_items = BeposoftCart.objects.filter(user=authUser)
            if not cart_items.exists():
                return Response(
                    {"status": "error", "message": "Cart is empty"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate order serializer (SAME AS OLD CODE)
            serializer = OrderSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {
                        "status": "error",
                        "message": "Validation failed",
                        "errors": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Aggregate cart → product-wise quantity
            product_data = {}
            product_ids = set()

            for item in cart_items:
                product = item.product
                product_ids.add(product.id)

                if product.id not in product_data:
                    product_data[product.id] = {
                        "product": product,
                        "quantity": Decimal(item.quantity),
                        "discount": Decimal(item.discount or 0),
                        "tax": Decimal(product.tax or 0),
                        "rate": Decimal(item.price or 0),
                        "description": item.note,
                    }
                else:
                    product_data[product.id]["quantity"] += Decimal(item.quantity)
                    product_data[product.id]["discount"] += Decimal(item.discount or 0)

            # Lock product rows & validate stock
            products = Products.objects.select_for_update().filter(id__in=product_ids)
            product_map = {p.id: p for p in products}

            stock_errors = []

            for product_id, data in product_data.items():
                product = product_map.get(product_id)

                if not product:
                    stock_errors.append({
                        "product_id": product_id,
                        "message": "Product not found"
                    })
                    continue

                requested_qty = int(data["quantity"])
                available_stock = product.stock - product.locked_stock

                if requested_qty > available_stock:
                    stock_errors.append({
                        "product_id": product.id,
                        "product_name": product.name,
                        "requested_quantity": requested_qty,
                        "available_stock": available_stock,
                        "message": f"Out of stock. Only {available_stock} available."
                    })

            # Stop order creation if stock fails
            if stock_errors:
                return Response(
                    {
                        "status": "error",
                        "error_code": "OUT_OF_STOCK",
                        "message": "Some products are out of stock",
                        "errors": stock_errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # CREATE ORDER (EXACTLY LIKE OLD CODE)
            order = serializer.save()

            # Lock stock & create order items
            for product_id, data in product_data.items():
                product = product_map[product_id]
                qty = int(data["quantity"])

                # Products.objects.filter(id=product.id).update(
                #     locked_stock=F("locked_stock") + qty
                # )

                OrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=qty,
                    discount=data["discount"],
                    tax=data["tax"],
                    rate=data["rate"],
                    description=data["description"],
                )

            # Clear cart
            cart_items.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Order created successfully",
                    "data": OrderSerializer(order).data
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.error("Unexpected error during order creation", exc_info=True)
            traceback.print_exc()
            return Response(
                {
                    "status": "error",
                    "message": "An unexpected error occurred",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OrderItemCreateView(APIView):
    def post(self, request):
        serializer = OrderItemUpdateSerializer(data=request.data)

        if serializer.is_valid():
            order_id = serializer.validated_data.get('order').id
            product_id = serializer.validated_data.get('product').id
            size_id = serializer.validated_data.get('size').id if serializer.validated_data.get('size') else None
            variant_id = serializer.validated_data.get('variant').id if serializer.validated_data.get('variant') else None

            # Check if the product is already added to the order
            existing_item = OrderItem.objects.filter(
                order_id=order_id,
                product_id=product_id,
                size_id=size_id,
                variant_id=variant_id
            ).first()

            if existing_item:
                return Response(
                    {"error": "Product is already added to the order."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                with transaction.atomic():
                    serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except ValueError as ve:
                return Response({'error': str(ve)}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response(
                    {'error': 'An unexpected error occurred.', 'details': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class OrderListView(BaseTokenView):

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "")
            status_filter = request.GET.get("status", "")
            staff_filter = request.GET.get("staff", "")
            start_date = request.GET.get("start_date", "")
            end_date = request.GET.get("end_date", "")

            # Optimized queryset
            orders = Order.objects.select_related(
                "manage_staff", "customer", "state", "family"
            ).prefetch_related("warehouse").order_by("-id")

            if search:
                # If user types only digits like 6595,
                # match invoice ending exactly with 6595
                if search.isdigit():
                    orders = orders.filter(invoice__iregex=rf"{re.escape(search)}$")
                else:
                    # exact full invoice OR exact customer name
                    orders = orders.filter(
                        Q(invoice__icontains=search) |
                        Q(customer__name__icontains=search)
                    )

            if status_filter:
                orders = orders.filter(status__iexact=status_filter)

            if staff_filter:
                orders = orders.filter(manage_staff__name__icontains=staff_filter)

            if start_date:
                orders = orders.filter(order_date__gte=start_date)

            if end_date:
                orders = orders.filter(order_date__lte=end_date)

            # Count queries (keep this before pagination)
            invoice_counts = orders.aggregate(
                invoice_created_count=Count("id", filter=Q(status="Invoice Created")),
                invoice_approved_count=Count("id", filter=Q(status="Waiting For Confirmation"))
            )

            # Pagination
            paginator = StandardPagination()
            paginated_orders = paginator.paginate_queryset(orders, request)

            serializer = OrderdetailsSerializer(paginated_orders, many=True)

            results = serializer.data

            for idx, order in enumerate(paginated_orders):
                family = getattr(order, "family", None)

                results[idx]["family_id"] = family.id if family else None
                results[idx]["family_name"] = family.name if family else None

                results[idx]["locked_by"] = order.locked_by.username if order.locked_by else None
                results[idx]["locked_at"] = order.locked_at.isoformat() if order.locked_at else None

            return paginator.get_paginated_response({
                "invoice_created_count": invoice_counts["invoice_created_count"],
                "invoice_approved_count": invoice_counts["invoice_approved_count"],
                "results": results
            })

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Orders not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class MyOrderListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            orders = Order.objects.filter(
                manage_staff=authUser
            ).select_related("manage_staff").order_by("-id")

            serializer = MyOrderSerializer(orders, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Orders not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class InvoiceListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            orders = Order.objects.filter(
                manage_staff__department_id__name__in=["BDO", "BDM"]
            ).order_by("-id")

            serializer = InvoiceListSerializer(orders, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Orders not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class GSTOrderListView(BaseTokenView):
    def get(self, request):
        # follow the same get_user_from_token pattern as your DataLogListView
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        # base queryset: exclude the two invoice statuses and order by newest first
        qs = Order.objects.exclude(status__in=["Invoice Rejected", "Invoice Created"]).order_by('-id')
        # parse pagination params safely
        try:
            page = int(request.GET.get('page', 1))
            if page < 1:
                page = 1
        except (ValueError, TypeError):
            page = 1

        try:
            page_size = int(request.GET.get('page_size', 100))
            # optional: clamp page_size to a sane maximum
            if page_size < 1:
                page_size = 100
            elif page_size > 1000:
                page_size = 1000
        except (ValueError, TypeError):
            page_size = 100

        start = (page - 1) * page_size
        end = start + page_size

        total_count = qs.count()
        paginated_qs = qs[start:end]

        serializer = GSTOrderSerializer(paginated_qs, many=True)

        return Response({
            "page": page,
            "page_size": page_size,
            "count": total_count,
            "results": serializer.data,
        }, status=status.HTTP_200_OK)


class OrderListByStatusView(BaseTokenView):
    def get(self, request, status_value):
        """
        Returns the order list filtered by status (from the URL).
        Example URL: /api/orders/status/<status_value>/
        """
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Filter orders by status (case-insensitive)
            orders = Order.objects.select_related(
                "manage_staff", "customer", "state", "family"
            ).prefetch_related("warehouse").filter(
                status__iexact=status_value
            ).order_by("-id")

            # Optimize Count Queries for this status
            invoice_counts = orders.aggregate(
                invoice_created_count=Count("id", filter=Q(status="Invoice Created")),
                invoice_approved_count=Count("id", filter=Q(status="Waiting For Confirmation"))
            )

            serializer = OrderdetailsSerializer(orders, many=True)

            # Add family_id and family_name to each order in results
            results = serializer.data
            for idx, order in enumerate(orders):
                family = getattr(order, "family", None)
                results[idx]["family_id"] = family.id if family else None
                results[idx]["family_name"] = family.name if family else None
                results[idx]["locked_by"] = order.locked_by.username if order.locked_by else None
                results[idx]["locked_at"] = order.locked_at.isoformat() if order.locked_at else None

            response_data = {
                "invoice_created_count": invoice_counts["invoice_created_count"],
                "invoice_approved_count": invoice_counts["invoice_approved_count"],
                "results": results
            }
            return Response(response_data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Orders not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FamilyOrderSummaryView(BaseTokenView):
    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Dates in IST (order_date is a string "YYYY-MM-DD")
            today = timezone.localdate()
            month_start = today.replace(day=1)

            today_str = today.strftime("%Y-%m-%d")
            month_start_str = month_start.strftime("%Y-%m-%d")

            # Base queryset (exclude Invoice Rejected)
            base_qs = Order.objects.filter(~Q(status="Invoice Rejected"))

            # -------- per-family: TODAY --------
            tq = (
                base_qs.values("family_id", "family__name")
                .annotate(
                    today_count=Count("id", filter=Q(order_date=today_str)),
                    today_total_amount=Coalesce(
                        Sum("total_amount", filter=Q(order_date=today_str)), Value(0.0), output_field=FloatField()
                    ),

                    t_paid_count=Count("id", filter=Q(order_date=today_str, payment_status="paid")),
                    t_paid_total=Coalesce(Sum("total_amount", filter=Q(order_date=today_str, payment_status="paid")), Value(0.0), output_field=FloatField()),

                    t_cod_count=Count("id", filter=Q(order_date=today_str, payment_status="COD")),
                    t_cod_total=Coalesce(Sum("total_amount", filter=Q(order_date=today_str, payment_status="COD")), Value(0.0), output_field=FloatField()),

                    t_credit_count=Count("id", filter=Q(order_date=today_str, payment_status="credit")),
                    t_credit_total=Coalesce(Sum("total_amount", filter=Q(order_date=today_str, payment_status="credit")), Value(0.0), output_field=FloatField()),
                )
            )

            # -------- per-family: MONTH (1st -> today) --------
            mq = (
                base_qs.values("family_id", "family__name")
                .annotate(
                    month_count=Count(
                        "id",
                        filter=Q(order_date__gte=month_start_str, order_date__lte=today_str),
                    ),
                    month_total_amount=Coalesce(
                        Sum("total_amount", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str)),
                        Value(0.0), output_field=FloatField()
                    ),

                    m_paid_count=Count("id", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="paid")),
                    m_paid_total=Coalesce(Sum("total_amount", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="paid")), Value(0.0), output_field=FloatField()),

                    m_cod_count=Count("id", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="COD")),
                    m_cod_total=Coalesce(Sum("total_amount", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="COD")), Value(0.0), output_field=FloatField()),

                    m_credit_count=Count("id", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="credit")),
                    m_credit_total=Coalesce(Sum("total_amount", filter=Q(order_date__gte=month_start_str, order_date__lte=today_str, payment_status="credit")), Value(0.0), output_field=FloatField()),
                )
            )

            # Merge today + month rows by family_id
            by_family = {}
            for r in tq:
                by_family[r["family_id"]] = {
                    "family_id": r["family_id"],
                    "family_name": r["family__name"],
                    "today_count": r["today_count"],
                    "today_total_amount": float(r["today_total_amount"] or 0),

                    # placeholders; will be filled by month loop below
                    "month_count": 0,
                    "month_total_amount": 0.0,

                    "payment_status_summary": {
                        "today": {
                            "paid":   {"count": r["t_paid_count"],    "total": float(r["t_paid_total"]    or 0)},
                            "COD":    {"count": r["t_cod_count"],     "total": float(r["t_cod_total"]     or 0)},
                            "credit": {"count": r["t_credit_count"],  "total": float(r["t_credit_total"]  or 0)},
                        },
                        "month": {  # will be replaced in month loop
                            "paid":   {"count": 0, "total": 0.0},
                            "COD":    {"count": 0, "total": 0.0},
                            "credit": {"count": 0, "total": 0.0},
                        }
                    }
                }

            for r in mq:
                row = by_family.setdefault(r["family_id"], {
                    "family_id": r["family_id"],
                    "family_name": r["family__name"],
                    "today_count": 0,
                    "today_total_amount": 0.0,
                    "payment_status_summary": {
                        "today": {
                            "paid":   {"count": 0, "total": 0.0},
                            "COD":    {"count": 0, "total": 0.0},
                            "credit": {"count": 0, "total": 0.0},
                        },
                        "month": {}
                    }
                })

                row["month_count"] = r["month_count"]
                row["month_total_amount"] = float(r["month_total_amount"] or 0)

                row["payment_status_summary"]["month"] = {
                    "paid":   {"count": r["m_paid_count"],    "total": float(r["m_paid_total"]    or 0)},
                    "COD":    {"count": r["m_cod_count"],     "total": float(r["m_cod_total"]     or 0)},
                    "credit": {"count": r["m_credit_count"],  "total": float(r["m_credit_total"]  or 0)},
                }

            # List sorted by family name
            results = sorted(by_family.values(), key=lambda x: (x["family_name"] or "").lower())

            # -------- overall aggregations (sum of families) --------
            overall = {
                "today_count": sum(r["today_count"] for r in results),
                "today_total_amount": float(sum(r["today_total_amount"] for r in results)),
                "month_count": sum(r["month_count"] for r in results),
                "month_total_amount": float(sum(r["month_total_amount"] for r in results)),
                "payment_status_summary": {
                    "today": {
                        "paid":   {"count": sum(r["payment_status_summary"]["today"]["paid"]["count"]     for r in results),
                                   "total": float(sum(r["payment_status_summary"]["today"]["paid"]["total"]  for r in results))},
                        "COD":    {"count": sum(r["payment_status_summary"]["today"]["COD"]["count"]      for r in results),
                                   "total": float(sum(r["payment_status_summary"]["today"]["COD"]["total"]   for r in results))},
                        "credit": {"count": sum(r["payment_status_summary"]["today"]["credit"]["count"]   for r in results),
                                   "total": float(sum(r["payment_status_summary"]["today"]["credit"]["total"] for r in results))},
                    },
                    "month": {
                        "paid":   {"count": sum(r["payment_status_summary"]["month"]["paid"]["count"]     for r in results),
                                   "total": float(sum(r["payment_status_summary"]["month"]["paid"]["total"]  for r in results))},
                        "COD":    {"count": sum(r["payment_status_summary"]["month"]["COD"]["count"]      for r in results),
                                   "total": float(sum(r["payment_status_summary"]["month"]["COD"]["total"]   for r in results))},
                        "credit": {"count": sum(r["payment_status_summary"]["month"]["credit"]["count"]   for r in results),
                                   "total": float(sum(r["payment_status_summary"]["month"]["credit"]["total"] for r in results))},
                    },
                },
            }

            return Response(
                {
                    "date": today_str,
                    "month_start": month_start_str,
                    "overall": overall,
                    "results": results,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class OrderDateReportView(BaseTokenView):

    def get(self, request, start_date, end_date):
        try:
            # Parse incoming dates
            start = datetime.strptime(start_date, "%Y-%m-%d").date()
            end = datetime.strptime(end_date, "%Y-%m-%d").date()

            # Optional family_id from frontend
            family_id = request.GET.get("family_id")

            # Prepare list manually since order_date is CharField
            filtered_orders = []

            queryset = Order.objects.all().select_related("manage_staff", "family")

            # Apply family filter if provided
            if family_id:
                queryset = queryset.filter(family_id=family_id)

            # Iterate and filter by converting order_date string to date
            for o in queryset:
                try:
                    order_dt = datetime.strptime(o.order_date, "%Y-%m-%d").date()
                    if start <= order_dt <= end:
                        filtered_orders.append(o)
                except:
                    continue

            # ---- Summaries ----
            total_amount = sum(o.total_amount for o in filtered_orders)

            non_rejected = [o for o in filtered_orders if o.status != "Invoice Rejected"]
            rejected = [o for o in filtered_orders if o.status == "Invoice Rejected"]

            order_data = [{
                "order_id": o.id,
                "staff_id": o.manage_staff.id if o.manage_staff else None,
                "staff_name": o.manage_staff.name if o.manage_staff else None,
                "amount": o.total_amount,
                "status": o.status,
                "family_id": o.family.id if o.family else None,
                "family_name": o.family.name if o.family else None,
                "order_date": o.order_date,
            } for o in filtered_orders]

            return Response({
                "status": True,
                "start_date": start_date,
                "end_date": end_date,
                "family_id": family_id,
                "summary": {
                    "total_orders": {
                        "count": len(filtered_orders),
                        "amount": total_amount,
                    },
                    "non_rejected_orders": {
                        "count": len(non_rejected),
                        "amount": sum(o.total_amount for o in non_rejected),
                    },
                    "rejected_orders": {
                        "count": len(rejected),
                        "amount": sum(o.total_amount for o in rejected),
                    },
                },
                "orders": order_data,
            })

        except Exception as e:
            return Response({
                "status": False,
                "error": str(e),
            }, status=400)
        

class ParcelServiceGroupedView(BaseTokenView):
    """
    GET /api/warehouse/parcel-service-grouped/?from=YYYY-MM-DD&to=YYYY-MM-DD&status=...&message_status=...
    Groups results by parcel_service.

    Each item includes:
      - shipped_date
      - invoice
      - customerName
      - total_amount (2 decimals)
      - parcel_amount
      - tracking_id
      - parcel_service
      - weight
      - actual_weight
      - volume_weight = (length * breadth * height) / 6000
      - box
      - average = parcel_amount per kg (uses actual_weight if >0, else volume_weight)
    """

    def get(self, request, *args, **kwargs):
        # ---- Base queryset + filters ----
        qs = Warehousedata.objects.all()

        date_from = request.query_params.get("from")
        date_to = request.query_params.get("to")
        status = request.query_params.get("status")
        message_status = request.query_params.get("message_status")
        parcel_service_id = request.query_params.get("parcel_service_id")
        parcel_service_name = request.query_params.get("parcel_service")

        if date_from:
            qs = qs.filter(shipped_date__gte=date_from)
        if date_to:
            qs = qs.filter(shipped_date__lte=date_to)
        if status:
            qs = qs.filter(status=status)
        if message_status:
            qs = qs.filter(message_status=message_status)
        if parcel_service_id:
            qs = qs.filter(parcel_service_id=parcel_service_id)
        if parcel_service_name:
            qs = qs.filter(parcel_service__name__iexact=parcel_service_name)

        # Efficiently pull related order data
        qs = qs.select_related(
            "parcel_service",
            "order",
            "order__billing_address",
            "order__customer",
            "order__company",
            "order__family",
            "order__manage_staff",
        ).order_by("-shipped_date", "-id")

        # ---- Helpers ----
        def _to_decimal(v):
            if v is None:
                return None
            try:
                return Decimal(str(v))
            except (InvalidOperation, ValueError, TypeError):
                return None

        def _to_float(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0

        def _volume_weight(w):
            # length, breadth, height are strings in model; treat missing as 0
            L = _to_float(w.length)
            B = _to_float(w.breadth)
            H = _to_float(w.height)
            if L <= 0 or B <= 0 or H <= 0:
                return None
            return round((L * B * H) / 6000.0, 2)

        def _customer_name(w):
            # Prefer shipping/billing name if present; else fallback to Customer.name
            if w.order and w.order.billing_address and w.order.billing_address.name:
                return w.order.billing_address.name
            if w.order and w.order.customer and w.order.customer.name:
                return w.order.customer.name
            return None

        def _average_per_kg(parcel_amount, actual_weight, vol_weight):
            amt = _to_decimal(parcel_amount) or Decimal("0")
            # Prefer actual weight; if missing/zero, use volume weight
            base_wt = _to_decimal(actual_weight) or None
            if (base_wt is None) or (base_wt <= 0):
                base_wt = _to_decimal(vol_weight) if vol_weight is not None else None
            if base_wt is None or base_wt <= 0:
                return None
            try:
                avg = amt / base_wt
                # return as 2-decimal string to mirror toFixed(2) vibe
                return f"{avg:.2f}"
            except (InvalidOperation, ZeroDivisionError):
                return None

        # ---- Build grouped payload ----
        grouped = []
        services = (
            qs.values("parcel_service__id", "parcel_service__name")
              .distinct()
              .order_by("parcel_service__name")
        )

        # Overall summary
        overall = qs.aggregate(
            total_boxes=Count("id"),
            total_actual_weight=Sum("actual_weight"),
            total_parcel_amount=Sum("parcel_amount"),
        )

        for svc in services:
            svc_id = svc["parcel_service__id"]
            svc_name = svc["parcel_service__name"] or None
            svc_qs = qs.filter(parcel_service_id=svc_id)

            # Per-service summary
            svc_summary = svc_qs.aggregate(
                boxes=Count("id"),
                actual_weight=Sum("actual_weight"),
                parcel_amount=Sum("parcel_amount"),
            )

            items = []
            for w in svc_qs:
                vol_wt = _volume_weight(w)
                inv = w.order.invoice if (w.order and w.order.invoice) else None
                total_amount = (
                    f"{_to_decimal(w.order.total_amount) or Decimal('0'):.2f}"
                    if w.order else "0.00"
                )
                customerName = _customer_name(w)

                item = {
                    "shipped_date": w.shipped_date,
                    "invoice": inv,
                    "customerName": customerName,
                    "total_amount": total_amount,
                    "parcel_amount": w.parcel_amount,
                    "tracking_id": w.tracking_id,
                    "parcel_service": svc_name,
                    "weight": w.weight,
                    "actual_weight": w.actual_weight,
                    "volume_weight": vol_wt,
                    "box": w.box,
                    "average": _average_per_kg(
                        w.parcel_amount, w.actual_weight, vol_wt
                    ),
                }
                items.append(item)

            grouped.append({
                "parcel_service_id": svc_id,
                "parcel_service_name": svc_name,
                "summary": {
                    "boxes": svc_summary["boxes"],
                    "actual_weight": svc_summary["actual_weight"],
                    "parcel_amount": svc_summary["parcel_amount"],
                },
                "items": items,
            })

        return Response({
            "summary": overall,
            "services": grouped,
        })

class LockOrderView(BaseTokenView):
    def post(self, request, order_id):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        try:
            order = Order.objects.get(id=order_id)

            if order.locked_by and order.locked_by != user:
                return Response({"message": "Order already in use"}, status=423)  # 423 Locked

            order.locked_by = user
            order.locked_at = timezone.now()
            order.save()

            return Response({"message": "Order locked"}, status=200)

        except Order.DoesNotExist:
            return Response({"message": "Order not found"}, status=404)
        except Exception as e:
            return Response({"message": str(e)}, status=500)
   
class UnlockOrderView(BaseTokenView):
    def post(self, request, order_id):
        try:

            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response


            order = Order.objects.get(id=order_id)

            if order.locked_by == authUser:
                order.locked_by = None
                order.locked_at = None
                order.save()
                return Response({"status": "unlocked"}, status=status.HTTP_200_OK)

            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        except Order.DoesNotExist:
            return Response({"error": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
               
class OrderUpdateView(BaseTokenView):
    def put(self, request, pk):
        try:
            # Get the user from the token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Get the order object to update
            order = get_object_or_404(Order, pk=pk)

            # Use partial=True to allow only provided fields to be updated
            # So if cod_amount or shipping_mode are not provided, it won't cause issues
            serializer = OrderSerializer(order, data=request.data, partial=True)
            if serializer.is_valid():
                # Save the updated order
                serializer.save()
                # Return the updated data in the response
                return Response(serializer.data, status=status.HTTP_200_OK)

            # If the serializer is not valid, return the errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CustomerOrderItems(BaseTokenView):
    def get(self, request, order_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            # Use select_related to fetch related objects in a single query
            order = Order.objects.select_related('manage_staff').filter(pk=order_id).first()
            if not order:
                return Response({"status": "error", "message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)
            
            # Use prefetch_related to fetch related order items in a single query
            orderItems = OrderItem.objects.filter(order=order_id).select_related('product')
            if not orderItems.exists():
                return Response({"status": "error", "message": "No order items found"}, status=status.HTTP_404_NOT_FOUND)
            
            grv_qs = GRVModel.objects.filter(order_id=order_id)
            
            manage_staff_designation = order.manage_staff.designation
            orderSerilizer = OrderModelSerilizer(order, many=False)
            serializer = OrderItemModelSerializer(orderItems, many=True, context={'manage_staff_designation': manage_staff_designation})

            grv_serializer = GRVLedgerSerializer(grv_qs, many=True)

            return Response(
                {
                    "order": orderSerilizer.data, 
                    "items": serializer.data,
                    "grv": grv_serializer.data 
                    }, 
                    status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Orders not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



logger = logging.getLogger(__name__)


class ShippingManagementView(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order = Order.objects.filter(pk=pk).first()
            if not order:
                return Response({"status": "error", "message": "Order not found"},
                                status=status.HTTP_404_NOT_FOUND)

            old_status = order.status
            new_status = request.data.get("status", old_status)

            # make the update atomic so Order.save() can use select_for_update()
            with transaction.atomic():
                serializer = OrderSerializer(order, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()


                    return Response({"status": "success", "message": "Order updated successfully"},
                                    status=status.HTTP_200_OK)

                return Response({"status": "error", "message": "Invalid data", "errors": serializer.errors},
                                status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductAttributeCreate(BaseTokenView):
    def  post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            serializer = AttributesModelSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(created_user = authUser)
                return Response({"status": "success", "message": "Product attribute created successfully"}, status=status.HTTP_201_CREATED)
            return Response({"status": "error", "message": "Invalid data", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
            

class ProductAttributeListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            attributes = Attributes.objects.all()
            serializer = AttributesModelSerializer(attributes, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        




class ProductAttributeView(BaseTokenView):

    def get_user_and_attribute(self, request, pk):
        authUser, error_response = self.get_user_from_token(request)
        if error_response:
            return None, error_response

        attribute = get_object_or_404(Attributes, pk=pk)
        return attribute, None

    def put(self, request, pk):
        attribute, error_response = self.get_user_and_attribute(request, pk)
        if error_response:
            return error_response

        serializer = AttributesModelSerializer(attribute, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({"status": "success", "message": "Attribute updated successfully"}, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        attribute, error_response = self.get_user_and_attribute(request, pk)
        if error_response:
            return error_response
        try:
            attribute.delete()
            return Response({"status": "success", "message": "Attribute deleted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ProductWiseReportView(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order_items = OrderItem.objects.select_related(
                'product', 'order', 'order__manage_staff'
            ).prefetch_related(
                'order__manage_staff__allocated_states'
            )

            serializer = ProductWiseReportSerializer(order_items, many=True)
            return Response({
                "message": "Product-wise report fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred while generating report",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductWiseFilterReportView(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # --- Get filters from query params ---
            family_name = request.query_params.get("family")
            start_date = request.query_params.get("start_date")
            end_date = request.query_params.get("end_date")

            order_items = OrderItem.objects.select_related(
                "product",
                "order",
                "order__manage_staff",
                "order__family",
                "order__state",
            ).prefetch_related(
                "order__manage_staff__allocated_states"
            )

            # --- Apply family filter ---
            if family_name:
                order_items = order_items.filter(order__family__name__iexact=family_name)

            # --- Apply date range filter ---
            if start_date:
                try:
                    start_dt = datetime.strptime(start_date, "%Y-%m-%d").date()
                    order_items = order_items.filter(order__order_date__gte=start_dt)
                except ValueError:
                    return Response(
                        {"status": "error", "message": "Invalid start_date format. Use YYYY-MM-DD"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            if end_date:
                try:
                    end_dt = datetime.strptime(end_date, "%Y-%m-%d").date()
                    order_items = order_items.filter(order__order_date__lte=end_dt)
                except ValueError:
                    return Response(
                        {"status": "error", "message": "Invalid end_date format. Use YYYY-MM-DD"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            serializer = ProductWiseReportSerializer(order_items, many=True)
            return Response(
                {
                    "message": "Product-wise report fetched successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while generating report",
                    "errors": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


logger = logging.getLogger(__name__)

class ProductAttributeCreateValue(BaseTokenView):
    def post(self, request):
        authUser, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        serializer = ProductAttributeModelSerilizer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Attribute value created successfully: {serializer.data}")
            return Response({"status": "success", "message": "Attribute value created successfully"}, status=status.HTTP_201_CREATED)
        return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            attributes_values = ProductAttribute.objects.all()
            serializer = ProductAttributeModelSerilizer(attributes_values, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        
        


class ProductAttributeListValue(BaseTokenView):
    def get(self,request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            attributes_values = ProductAttribute.objects.filter(attribute=pk)
            serializer = ProductAttributeModelSerilizer(attributes_values, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Attribute not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class ProductAttributeValueUpdate(BaseTokenView):
    def put(self, request, pk=None):
        authUser, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        if not pk:
            return Response({"status": "error", "message": "ID is required for update"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            attribute = ProductAttribute.objects.get(pk=pk)
        except ProductAttribute.DoesNotExist:
            return Response({"status": "error", "message": "Attribute not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ProductAttributeModelSerilizer(attribute, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Attribute value updated successfully: {serializer.data}")
            return Response({"status": "success", "message": "Attribute value updated successfully"}, status=status.HTTP_200_OK)
        return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class ProductAttributeValueDelete(APIView):
    def delete(self, request, pk):
        try:
            attribute_value = ProductAttribute.objects.filter(pk=pk).first()
            if not attribute_value:
                return Response({"status": "error", "message": "Attribute value not found"}, status=status.HTTP_404_NOT_FOUND)
            
            attribute_value.delete()
            return Response({"status": "success", "message": "Attribute value deleted"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class StaffCustomersView(BaseTokenView):
    def get(self,request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            customers = Customers.objects.filter(manager = authUser)
            if not customers:
                return Response({"status": "error", "message": "No customers found"}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = CustomerModelSerializer(customers, many=True)
            return Response({"data":serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        

class Cart(BaseTokenView):
    PRODUCT_TYPE_SINGLE = 'single'
    
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            product = get_object_or_404(Products, pk=request.data.get("product"))
            quantity = request.data.get("quantity")
            
            if authUser.designation in ['BDM', 'BDO']:
                price = product.selling_price
            else:
                price = product.retail_price
                
            
            return self.add_product_in_cart(product, quantity, authUser, price)
           
        except KeyError as e:
            return Response({"status": "error", "message": f"Missing field: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:

            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def add_product_in_cart(self, product, quantity, user, price):
        existing_cart_item = BeposoftCart.objects.filter(product=product, user=user).first()
        
        if existing_cart_item:
            # If the product is already in the cart, return an error message
            return Response({"status": "error", "message": "Product already exists in the cart"}, status=status.HTTP_400_BAD_REQUEST)
       
        BeposoftCart.objects.create(product=product, user=user, quantity=quantity, price=price)
        return Response({"status": "success", "message": "Product added to cart"}, status=status.HTTP_201_CREATED)


    



class StaffDeleteCartProduct(BaseTokenView):
    
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cartItem = get_object_or_404(BeposoftCart, pk=pk)
            serializer = BepocartSerializers(cartItem, data=request.data, partial=True)
            

            if serializer.is_valid():
                serializer.save()
                cartItem.refresh_from_db()  # Refresh the instance to get updated values
                return Response({"status": "success", "message": "Cart item updated successfully."}, status=status.HTTP_200_OK)
            
            return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self, request, pk):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cartItem = get_object_or_404(BeposoftCart, pk=pk)
            cartItem.delete()
            return Response({"status": "success", "message": "Cart item deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

        except Exception as e:
            # Handle exceptions and return error response
            return Response({"status": "error", "message": "An error occurred while deleting the cart item.", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StaffDeleteCartProductAll(BaseTokenView):

    def delete(self, request):
        try:
            authUser, error_response = BaseTokenView().get_user_from_token(request)
            if error_response:
                return error_response

            # To delete only current user's cart items
            BeposoftCart.objects.filter(user=authUser).delete()

            return Response({"status": "success", "message": "All cart items deleted."}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "Failed to delete all cart items.", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StaffcartStoredProductsView(BaseTokenView):
    def get(self,request):
        try :
        
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            if not hasattr(authUser, 'designation') or authUser.designation is None:
                return Response(
                    {"status": "error", "message": "User does not have a designation"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            staffItems = BeposoftCart.objects.filter(user = authUser)

            serializers = BepocartSerializersView(staffItems, many=True)
            return Response({"data":serializers.data},status=status.HTTP_200_OK)
        
        except Exception as  e :
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        
class CreateBankAccountView(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate the user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            data = request.data
            if isinstance(data, dict):
                data = [data]
            
            if not isinstance(data, list):
                return Response(
                    {"status": "error", "message": "Invalid data format. Must be a dictionary or list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = BankSerializer(data=data, many=True)
            if serializer.is_valid():
                serializer.save(created_user=authUser)
                return Response(
                    {"status": "success", "message": "Bank account(s) created successfully."},
                    status=status.HTTP_201_CREATED,
                )
            
            return Response(
                {"status": "error", "message": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        
class BankView(BaseTokenView):
    def get(self,request):
        try :
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            banks = Bank.objects.all()
            serializer = BankSerializer(banks, many=True)
            return Response({"data":serializer.data},status=status.HTTP_200_OK)
        except Exception as  e :
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



class BankAccountView(BaseTokenView):
    def get(self,request):
        try :
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            bankAccount = Bank.objects.filter(user = authUser)
            serializer = BankSerializer(bankAccount, many=True)
            return Response({"data":serializer.data},status=status.HTTP_200_OK)
        except Exception as  e :
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            bank = get_object_or_404(Bank, pk=pk)
            serializer = BankSerializer(bank, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success"}, status=status.HTTP_200_OK)
            return Response({"error":serializer.errors})
        except Exception as e :
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
        
class ExistedOrderAddProducts(BaseTokenView):
    
    def post(self, request, pk):
        try:
            
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Retrieve the order instance using the primary key (pk)
            order = get_object_or_404(Order, pk=pk)
          
            product = get_object_or_404(Products, pk=request.data.get("product"))
            quantity = request.data.get("quantity")
            if quantity is None:
                return Response({"status": "error", "message": "Quantity is required."}, status=status.HTTP_400_BAD_REQUEST)

            

            return self.add_single_product_to_cart(product, order, quantity)
        
        except KeyError as e:
            return Response({"status": "error", "message": f"Missing field: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def add_single_product_to_cart(self, product, order, quantity):
        """Add a single product to the cart."""
        OrderItem.objects.create(
            product=product,            # Pass the Product instance
            rate=product.selling_price,  # Set rate based on product
            order=order,                 # Pass the Order instance directly
            quantity=quantity,
            tax = product.tax,
        )
        return Response({"status": "success", "message": "Product added to cart"}, status=status.HTTP_201_CREATED)
        
    
class RemoveExistsOrderItems(BaseTokenView):
    
    def get_order_item(self, pk):
        try:
            order_item = get_object_or_404(OrderItem, pk=pk)
            return order_item
        except OrderItem.DoesNotExist:
            return None

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order_item = self.get_order_item(pk)
            if not order_item:
                return Response({"status": "error", "message": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)

            order_item.delete()
            return Response({"status": "success"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self, request, pk):
        authUser, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        with transaction.atomic():
            item = get_object_or_404(OrderItem, pk=pk)

            serializer = ExistedOrderAddProductsSerializer(
                item, data=request.data, partial=True
            )
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"status": "success", "data": serializer.data},
                    status=status.HTTP_200_OK
                )

        return Response(
            {"status": "error", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

class OrderTotalAmountSave(BaseTokenView):
    def put(self,request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            order = get_object_or_404(Order, pk=pk)
            serializer = OrderSerializer(order, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Order updated successfully"}, status=status.HTTP_200_OK)
            return Response({"status": "error", "message": "Invalid data provided"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e :
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class BankReceiptListCreateView(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            request.data['created_by'] = authUser.pk

            serializer = BankReceiptSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"status": "success", "message": "Bank Receipt created successfully"},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            receipts = BankReceipt.objects.all().order_by('-id')
            serializer = BankReceiptSerializer(receipts, many=True)
            return Response(
                {"status": "success", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        
class CreateAdvanceReceipt(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            request.data['created_by'] = authUser.pk

            # DO NOT overwrite 'order' here, accept it from the request
            serializer = AdvanceReceiptSerializer(data=request.data)
            if serializer.is_valid():
                receipt = serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Advance Receipt created successfully",
                        "data": AdvanceReceiptSerializer(receipt).data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch all Advance Receipts - filter by user if needed
            receipts = AdvanceReceipt.objects.all().order_by('-id')
            serializer = AdvanceReceiptSerializer(receipts, many=True)
            return Response(
                {"status": "success", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CreateReceiptAgainstInvoice(BaseTokenView):
    def post(self, request, pk):
        try:
            # Authenticate user from token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order = get_object_or_404(Order, pk=pk)
            
            request.data['order'] = order.pk
            request.data['customer'] = order.customer.pk
            request.data['created_by'] = authUser.pk
            
            serializer = PaymentRecieptSerializers(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Receipt created successfully"}, status=status.HTTP_200_OK)

         
            return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log the exception message for debugging
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class AllReceiptsView(APIView):
    def get(self, request):
        # Fetch all and annotate with type
        advance_receipts = [
            {**receipt, "receipt_type": "advance"} 
            for receipt in AdvanceReceiptSerializer(AdvanceReceipt.objects.all(), many=True).data
        ]
        bank_receipts = [
            {**receipt, "receipt_type": "bank"} 
            for receipt in BankReceiptSerializer(BankReceipt.objects.all(), many=True).data
        ]
        payment_receipts = [
            {**receipt, "receipt_type": "payment"} 
            for receipt in PaymentRecieptSerializers(PaymentReceipt.objects.all(), many=True).data
        ]

        # Combine and sort by ID descending
        all_receipts = advance_receipts + bank_receipts + payment_receipts
        sorted_receipts = sorted(all_receipts, key=lambda x: x["id"], reverse=True)

        return Response({
            "receipts": sorted_receipts
        }, status=status.HTTP_200_OK)

        
class AdvanceReceiptListView(APIView):
    def get(self, request):
        try:
            receipts = AdvanceReceipt.objects.all().order_by('-id')
            serializer = AdvanceReceiptSerializer(receipts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class BankReceiptListView(APIView):
    def get(self, request):
        try:
            receipts = BankReceipt.objects.all().order_by('-id')
            serializer = BankReceiptSerializer(receipts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OrderReceiptListView(APIView):
    def get(self, request):
        try:
            receipts = PaymentReceipt.objects.all().order_by('-id')
            serializer = PaymentRecieptSerializers(receipts, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AdvanceReceiptDetailView(APIView):
    def get(self, request, pk):
        try:
            receipt = get_object_or_404(AdvanceReceipt, pk=pk)
            serializer = AdvanceReceiptSerializer(receipt)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            receipt = get_object_or_404(AdvanceReceipt, pk=pk)
            serializer = AdvanceReceiptSerializer(receipt, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def delete(self, request, pk):
        try:
            receipt = get_object_or_404(AdvanceReceipt, pk=pk)
            receipt.delete()
            return Response({'message': 'Advance receipt deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class BankReceiptDetailView(APIView):
    def get(self, request, pk):
        try:
            receipt = get_object_or_404(BankReceipt, pk=pk)
            serializer = BankReceiptSerializer(receipt)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            receipt = get_object_or_404(BankReceipt, pk=pk)
            serializer = BankReceiptSerializer(receipt, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            receipt = get_object_or_404(BankReceipt, pk=pk)
            receipt.delete()
            return Response({'message': 'Bank receipt deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class OrderReceiptDetailView(APIView):
    def get(self, request, pk):
        try:
            receipt = get_object_or_404(PaymentReceipt, pk=pk)
            serializer = PaymentRecieptSerializers(receipt)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            receipt = get_object_or_404(PaymentReceipt, pk=pk)
            serializer = PaymentRecieptSerializers(receipt, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
   

class CustomerOrderLedgerdata(BaseTokenView):
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            customer = get_object_or_404(Customers, pk=pk)

            # ---- ORDER LEDGER ----
            ledger = (
                Order.objects
                .filter(customer=customer)
                .annotate(
                    return_amount=Coalesce(
                        Sum("grvmodel__price", filter=Q(grvmodel__remark="return")),
                        Value(0),
                        output_field=DecimalField(max_digits=10, decimal_places=2)
                    ),
                    refund_amount=Coalesce(
                        Sum("grvmodel__price", filter=Q(grvmodel__remark="refund")),
                        Value(0),
                        output_field=DecimalField(max_digits=10, decimal_places=2)
                    ),
                    cod_return_amount=Coalesce(
                        Sum("grvmodel__cod_amount", filter=Q(grvmodel__remark="cod_return")),
                        Value(0),
                        output_field=DecimalField(max_digits=10, decimal_places=2)
                    ),
                    exchange_amount=Coalesce(
                        Sum("grvmodel__price", filter=Q(grvmodel__remark="exchange")),
                        Value(0),
                        output_field=DecimalField(max_digits=10, decimal_places=2)
                    ),
                )
                .order_by("order_date")
            )

            ledger_serializer = LedgerSerializers(ledger, many=True)

            # ---- ADVANCE RECEIPTS ----
            advance_receipts = AdvanceReceipt.objects.filter(customer=customer).order_by("-id")
            advance_serializer = AdvanceReceiptSerializer(advance_receipts, many=True)

            # ---- PAYMENT RECEIPTS ----
            payment_receipts = (
                PaymentReceipt.objects
                .filter(order__customer=customer)
                .select_related("bank", "created_by", "order")
                .order_by("-id")
            )
            payment_serializer = PaymentRecieptsViewSerializers(payment_receipts, many=True)

            # ---- GRV DATA ----
            grv_qs = (
                GRVModel.objects
                .filter(order__customer=customer)
                .select_related("order")
                .order_by("-date", "-id")
            )
            grv_serializer = GRVLedgerSerializer(grv_qs, many=True)

            # ---- REFUND RECEIPTS ----
            refund_receipts = (
                RefundReceipt.objects
                .filter(customer=customer)
                .select_related("bank", "created_by", "invoice", "customer")
                .order_by("-date", "-id")
            )

            refund_serializer = RefundReceiptSerializer(refund_receipts, many=True)

            # ---- ADVANCE TRANSFERS (SENT BY CUSTOMER → LEDGER) ----
            sent_transfers = (
                AdvanceAmountTransfer.objects
                .filter(send_from=customer)
                .select_related("send_from", "send_to", "created_by")
                .order_by("date", "id")
            )

            sent_transfer_serializer = AdvanceAmountTransferSerializer(
                sent_transfers, many=True
            )

            # ---- ADVANCE TRANSFERS (RECEIVED BY CUSTOMER) ----
            received_transfers = (
                AdvanceAmountTransfer.objects
                .filter(send_to=customer)
                .select_related("send_from", "send_to", "created_by")
                .order_by("date", "id")
            )

            advance_transfer_serializer = AdvanceAmountTransferSerializer(
                received_transfers, many=True
            )

            return Response(
                {
                    "data": {
                        "ledger": ledger_serializer.data,
                        "ledger_sent_transfers": sent_transfer_serializer.data, 
                        "refund_receipts": refund_serializer.data,
                        "advance_receipts": advance_serializer.data,
                        "payment_receipts": payment_serializer.data,
                        "grv": grv_serializer.data,
                        "advance_transfers": advance_transfer_serializer.data,
                    }
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

            
# class CreatePerfomaInvoice(BaseTokenView):
#     def post(self, request):
#         try:
#             # Authenticate user
#             authUser, error_response = self.get_user_from_token(request)
#             if error_response:
#                 return error_response
#             warehouse_id = request.data.get("warehouse_id")
#             if not warehouse_id:
#                 return Response({"status": "error", "message": "Warehouse ID is required"}, status=status.HTTP_400_BAD_REQUEST)

#             # Retrieve and validate the warehouse object
#             warehouse = get_object_or_404(WareHouse, pk=warehouse_id)
#             cart_items = BeposoftCart.objects.filter(user=authUser)
#             serializer = PerfomaInvoiceOrderSerializers(data=request.data)
#             if not serializer.is_valid():
#                 return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
#          # Retrieve cart items and validate serializer
            
#               # Create order
#             order = serializer.save()

#             # Manually assign the warehouse to the order
#             order.warehouses_obj = warehouse
#             order.save()  
#             for item_data in cart_items:
#                 product = get_object_or_404(Products, pk=item_data.product.pk)

#                 # Convert values to Decimal for consistency
#                 quantity = Decimal(item_data.quantity or 0)
#                 selling_price = Decimal(item_data.product.selling_price or 0)
#                 discount = Decimal(item_data.discount or 0)  # Handles None discount
#                 tax = Decimal(item_data.product.tax or 0)
#                 rate = Decimal(item_data.price or 0)
               

                

#                 # Check stock and decrement
#                 if product.stock < quantity:
#                     return Response({"status": "error", "message": "Insufficient stock for single product"}, status=status.HTTP_400_BAD_REQUEST)
#                 product.stock -= int(quantity)
#                 product.save()
            
               

#                 # Create order item for each valid cart item
#                 PerfomaInvoiceOrderItem.objects.create(
#                     order=order,
#                     product=product,
#                     quantity=int(quantity),
#                     discount=discount,
#                     tax=tax,
#                     rate=rate,
#                     description=item_data.note,
#                 )
            
#             # Clear cart after successful order creation
#             cart_items.delete()
#             return Response({"status": "success", "message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
#         except Exception as e:
#             logger.error("Unexpected error in CreateOrder view: %s", str(e))
#             return Response({"status": "error", "message": "An unexpected error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CreatePerfomaInvoice(BaseTokenView):

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            warehouse_id = request.data.get("warehouse_id")
            if not warehouse_id:
                return Response(
                    {"status": "error", "message": "warehouse_id is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            warehouse = get_object_or_404(WareHouse, id=warehouse_id)

            cart_items = (
                BeposoftCart.objects
                .select_related("product")
                .filter(user=authUser)
            )

            if not cart_items.exists():
                return Response(
                    {"status": "error", "message": "Cart is empty"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = PerfomaInvoiceOrderSerializers(data=request.data)
            serializer.is_valid(raise_exception=True)

            with transaction.atomic():

                # Create order
                order = serializer.save(
                    manage_staff=authUser,
                    warehouses_obj=warehouse
                )

                for cart in cart_items:

                    product = cart.product

                    quantity = int(cart.quantity)
                    rate = Decimal(cart.price or product.selling_price or 0)
                    discount = Decimal(cart.discount or 0)
                    tax = Decimal(product.tax or 0)

                    # ❌ NO STOCK LOCK / NO STOCK REDUCTION
                    PerfomaInvoiceOrderItem.objects.create(
                        order=order,
                        product=product,
                        quantity=quantity,
                        rate=rate,
                        discount=discount,
                        tax=tax,
                        description=cart.note
                    )

                # Clear cart after success
                cart_items.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Performa invoice created successfully",
                    "invoice": order.invoice
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            logger.exception("CreatePerfomaInvoice failed")
            return Response(
                {
                    "status": "error",
                    "message": "Internal server error",
                    "details": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class PerfomaInvoiceListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Assuming 'created_at' is the field representing the order creation date
            orders = PerfomaInvoiceOrder.objects.all().order_by('-order_date')

            # Serialize the orders
            serializer = PerfomaInvoiceProductsSerializers(orders, many=True)
            
            return Response({"data":serializer.data}, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Orders not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
class PerfomaInvoiceDetailView(BaseTokenView):
    def get(self, request, invoice):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            perfoma = PerfomaInvoiceOrder.objects.filter(invoice=invoice).first()
            if not perfoma:
                return Response({"status": "error", "message": "Order not found"}, status=status.HTTP_204_NO_CONTENT)
            
            serializer = PerfomaInvoiceProductsSerializers(perfoma,context={"manage_staff_designation": perfoma.manage_staff.designation})
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PerformaOrderStaff(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            perfoma_orders = PerfomaInvoiceOrder.objects.filter(
                manage_staff=authUser
            ).order_by('order_date')  # Replace 'created_at' with your actual date field

            serializer = PerformaOrderListSerilaizer(perfoma_orders, many=True)

            return Response({
                "message": "Perfoma orders successfully retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CreateCompnayDetailsView(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            # Check if the incoming data is single or multiple
            data = request.data
            if isinstance(data, dict):
                # Single record: Wrap it in a list to reuse the bulk handling logic
                data = [data]
            
            if not isinstance(data, list):
                return Response(
                    {"status": "error", "message": "Invalid data format. Must be a dictionary or list of dictionaries."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            # Pass user to the serializer context
            serializer = CompanyDetailsSerializer(data=data, many=True, context={'user': authUser})
            if serializer.is_valid():
                serializer.save()  # Handles both single and multiple
                return Response(
                    {"status": "success", "message": "Company details created successfully"},
                    status=status.HTTP_201_CREATED,
                )
            
            # Return validation errors
            return Response(
                {"status": "error", "message": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            company = Company.objects.all()
            serializer = CompanyDetailsSerializer(company, many=True)
            return Response(
                    {"data": serializer.data,"status":"success"},
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CallLogDataView(APIView):
    def post(self, request, created_by_id):
        data = request.data.copy()

        try:
            user = User.objects.get(pk=created_by_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        data['created_by'] = user.id
        data['family_name'] = user.family.id if user.family else None

        serializer = CallLogSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

  
class CallLogView(APIView):
    def get(self, request):
        logs = CallLog.objects.all()
        serializer = CallLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class WarehouseDataView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            if isinstance(request.data, list):
                serializer = WarehouseBoxesDataSerializer(data=request.data, many=True)
            else:
                serializer = WarehouseBoxesDataSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()
                return Response({"status":"success","data":serializer.data}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            data = Warehousedata.objects.all()
            serializer = WarehouseBoxesDataSerializer(data, many=True)
            return Response({"data":serializer.data,"status":"success"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
class WarehouseDetailView(BaseTokenView):
    def put(self,request,pk):
        try:
            authUser,error_response=self.get_user_from_token(request)  
            if error_response:
                return error_response
            warehousedata = get_object_or_404(Warehousedata,pk=pk)
            serializer = WarehouseUpdateSerializers(warehousedata, data=request.data,partial =True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehousedata = get_object_or_404(Warehousedata, pk=pk)
            warehousedata.delete()
            return Response({"status": "success", "message": "Warehouse data deleted"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                            
       
class DailyGoodsView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            warehouse = Warehousedata.objects.all()
            
            seen_dates = set()
            response_data = []

            for box_detail in warehouse:
                if (box_detail.shipped_date not in seen_dates) and (box_detail.shipped_date is not None):
                    boxes_for_date = warehouse.filter(shipped_date=box_detail.shipped_date)
                    total_weight = 0
                    for box in boxes_for_date:
                        try:
                            total_weight += float(box.weight)
                        except (ValueError, TypeError):
                            continue

                    total_volume_weight = 0
                    for box in boxes_for_date:
                        try:
                            length = float(box.length)
                            breadth = float(box.breadth)
                            height = float(box.height)
                            total_volume_weight += (length * breadth * height) / 6000
                        except (ValueError, TypeError):
                            continue

                    total_shipping_charge = 0
                    for box in boxes_for_date:
                        try:
                            total_shipping_charge += float(box.shipping_charge)
                        except (ValueError, TypeError):
                            continue

                    total_actual_weight = 0
                    for box in boxes_for_date:
                        try:
                            total_actual_weight += float(box.actual_weight)
                        except (ValueError, TypeError):
                            continue

                    total_parcel_amount = 0
                    for box in boxes_for_date:
                        try:
                            total_parcel_amount += float(box.parcel_amount)
                        except (ValueError, TypeError):
                            continue

                    total_boxes = boxes_for_date.count()

                    # Serialize the boxes for the date
                    serializer = WarehousedataSerializer(boxes_for_date, many=True)

                    # Add the data for the current shipped_date
                    response_data.append({
                        "shipped_date": box_detail.shipped_date,
                        "total_boxes": total_boxes,
                        "total_weight": round(total_weight, 2),
                        "total_volume_weight": round(total_volume_weight, 2),
                        "total_shipping_charge": round(total_shipping_charge, 2),
                        "total_actual_weight": round(total_actual_weight, 2),
                        "total_parcel_amount": round(total_parcel_amount, 2),
                        # "boxes": serializer.data
                    })

                    seen_dates.add(box_detail.shipped_date)

            # Sort by shipped_date descending
            response_data.sort(key=lambda x: x['shipped_date'], reverse=True)

            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DailyGoodsBydate(BaseTokenView):
    def get(self,request,date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
      
            warehouse_data = Warehousedata.objects.filter(shipped_date=date)
            if not warehouse_data.exists():
                return Response({"Order Not Found"})
            serializer = WarehousedataSerializer(warehouse_data, many=True)
            return Response(serializer.data,status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            
class WarehouseListView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            warehouses = Warehousedata.objects.all()

            # Serialize warehouse data
            serializer = WarehousedataSerializer(warehouses, many=True)

            # Group by invoice (storing invoice_id as well)
            grouped_data = {}
            for warehouse in serializer.data:
                invoice = warehouse.get("invoice", "No Invoice")  # Default if missing
                invoice_id = warehouse.get("order", None)  # Assuming 'order' is the invoice ID

                if invoice not in grouped_data:
                    grouped_data[invoice] = {
                        "invoice_id": invoice_id,
                        "invoice": invoice,
                        "warehouses": []
                    }
                grouped_data[invoice]["warehouses"].append(warehouse)

            # Convert dictionary to list format
            formatted_response = list(grouped_data.values())

            response_data = {
                "results": formatted_response
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Warehouse data not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WarehouseSummaryView(APIView):

    def get(self, request):
        try:
            order_id = request.GET.get("order", None)

            if order_id:
                base_qs = Warehousedata.objects.filter(order__id=order_id)
            else:
                base_qs = Warehousedata.objects.all()

            today = now().date()
            first_day_month = today.replace(day=1)
            last_30_days = today - timedelta(days=30)

            # keep upper bound as today, so future dated records do not affect month/30-day summaries
            qs_today = base_qs.filter(shipped_date=today)
            qs_month = base_qs.filter(
                shipped_date__gte=first_day_month,
                shipped_date__lte=today
            )
            qs_30_days = base_qs.filter(
                shipped_date__gte=last_30_days,
                shipped_date__lte=today
            )

            def safe_float(value):
                try:
                    if value in [None, "", "null"]:
                        return 0.0
                    return float(value)
                except Exception:
                    return 0.0

            # same as tracking report volume-weight logic
            def get_volume(obj):
                l = safe_float(obj.length)
                b = safe_float(obj.breadth)
                h = safe_float(obj.height)

                if l <= 0 or b <= 0 or h <= 0:
                    return 0.0

                return round((l * b * h) / 6000.0, 2)

            # same as tracking report row average logic
            def get_item_average(obj):
                parcel_amount = safe_float(obj.parcel_amount)
                actual_weight = safe_float(obj.actual_weight)
                volume_weight = get_volume(obj)

                base_weight = actual_weight if actual_weight > 0 else volume_weight
                if base_weight <= 0:
                    return 0.0

                return round(parcel_amount / base_weight, 2)

            def get_summary(qs):
                total_boxes = qs.count()

                # MATCH UI
                total_actual_weight_g = sum(safe_float(w.weight) for w in qs)
                total_weight_field = sum(safe_float(w.actual_weight) for w in qs)
                total_parcel_amount = sum(safe_float(w.parcel_amount) for w in qs)
                total_volume = sum(get_volume(w) for w in qs)

                # MATCH UI total average (sum of each row average)
                average = sum(get_item_average(w) for w in qs)

                total_actual_weight_kg = (
                    total_actual_weight_g / 1000 if total_actual_weight_g > 0 else 0
                )

                return {
                    "total_boxes": total_boxes,
                    "total_actual_weight_g": round(total_actual_weight_g, 2),
                    "total_actual_weight_kg": round(total_actual_weight_kg, 3),
                    "total_parcel_amount": round(total_parcel_amount, 2),
                    "average": round(average, 2),
                    "total_volume": round(total_volume, 2),
                    "total_weight_field": round(total_weight_field, 2),
                }

            today_summary = get_summary(qs_today)
            current_month_summary = get_summary(qs_month)
            last_30_days_summary = get_summary(qs_30_days)

            def get_service_summary(qs):
                result = {}

                for w in qs:
                    name = w.parcel_service.name if w.parcel_service else "Others"

                    if name not in result:
                        result[name] = {
                            "total_boxes": 0,
                            "total_actual_weight_g": 0.0,
                            "total_parcel_amount": 0.0,
                            "total_volume": 0.0,
                            "total_weight_field": 0.0,
                            "total_actual_weight_kg": 0.0,
                            "average": 0.0,
                        }

                    # MATCH UI
                    result[name]["total_boxes"] += 1
                    result[name]["total_actual_weight_g"] += safe_float(w.weight)
                    result[name]["total_parcel_amount"] += safe_float(w.parcel_amount)
                    result[name]["total_volume"] += get_volume(w)
                    result[name]["total_weight_field"] += safe_float(w.actual_weight)
                    result[name]["average"] += get_item_average(w)

                for service_name, data in result.items():
                    total_g = data["total_actual_weight_g"]
                    data["total_actual_weight_kg"] = round(
                        total_g / 1000 if total_g > 0 else 0, 3
                    )
                    data["total_actual_weight_g"] = round(data["total_actual_weight_g"], 2)
                    data["total_parcel_amount"] = round(data["total_parcel_amount"], 2)
                    data["total_volume"] = round(data["total_volume"], 2)
                    data["total_weight_field"] = round(data["total_weight_field"], 2)
                    data["average"] = round(data["average"], 2)

                return result

            today_services = get_service_summary(qs_today)
            month_services = get_service_summary(qs_month)
            days30_services = get_service_summary(qs_30_days)

            all_services = {}
            all_keys = (
                set(today_services.keys()) |
                set(month_services.keys()) |
                set(days30_services.keys())
            )

            default_service_data = {
                "total_boxes": 0,
                "total_actual_weight_g": 0.0,
                "total_parcel_amount": 0.0,
                "total_volume": 0.0,
                "total_weight_field": 0.0,
                "total_actual_weight_kg": 0.0,
                "average": 0.0,
            }

            for key in all_keys:
                all_services[key] = {
                    "today": today_services.get(key, default_service_data.copy()),
                    "current_month": month_services.get(key, default_service_data.copy()),
                    "last_30_days": days30_services.get(key, default_service_data.copy()),
                }

            return Response(
                {
                    "success": True,
                    "today_summary": today_summary,
                    "current_month_summary": current_month_summary,
                    "last_30_days_summary": last_30_days_summary,
                    "data": all_services,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OrderStatusCount(APIView):
    def get(self, request):
        try:
            required_statuses = [
                "Invoice Created",
                "Invoice Approved",
                "Waiting For Confirmation",
                "To Print",
                "Invoice Rejected",
                "Packing under progress",
                "Packed",
                "Ready to ship",
                "Shipped",
            ]

            today = now().date()
            month_start = today.replace(day=1)
            last_30_days = now() - timedelta(days=30)

            queryset = Order.objects.filter(status__in=required_statuses)

            # -------- Helper to insert zero counts ----------
            def normalize(data):
                formatted = {item["status"]: item["count"] for item in data}
                return [
                    {"status": st, "count": formatted.get(st, 0)}
                    for st in required_statuses
                ]

            # Today
            today_raw = (
                queryset.filter(updated_at__date=today)
                .values("status")
                .annotate(count=Count("id"))
            )
            today_data = normalize(today_raw)

            # Current Month
            current_month_raw = (
                queryset.filter(updated_at__date__gte=month_start)
                .values("status")
                .annotate(count=Count("id"))
            )
            current_month_data = normalize(current_month_raw)

            # Last 30 Days
            last_30_days_raw = (
                queryset.filter(updated_at__gte=last_30_days)
                .values("status")
                .annotate(count=Count("id"))
            )
            last_30_days_data = normalize(last_30_days_raw)

            return Response(
                {
                    "success": True,
                    "today": today_data,
                    "current_month": current_month_data,
                    "last_30_days": last_30_days_data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": "Failed to fetch data",
                    "error": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class WarehouseListViewbyDate(BaseTokenView):
    def get(self, request, shipped_date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Filter data by shipped_date passed in the URL
            warehouses = Warehousedata.objects.filter(shipped_date=shipped_date).order_by('id')

            if not warehouses.exists():
                return Response(
                    {"status": "error", "message": "No warehouse data found for this shipped date"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Serialize warehouse data
            serializer = WarehousedataSerializer(warehouses, many=True)

            # Group by invoice
            grouped_families = {}
            for warehouse in serializer.data:
                family = warehouse.get("family", "Bepocart")  # Default to Bepocart if no family found
                invoice_id = warehouse.get("order")
                invoice = warehouse.get("invoice") or "No Invoice"
                cod_amount = warehouse.get("cod_amount")
                box_count = warehouse.get("box_count")

                # Initialize family group if not exists
                if family not in grouped_families:
                    grouped_families[family] = {"family": family, "orders": []}

                # Check if invoice_id already exists in orders
                invoice_exists = next(
                    (order for order in grouped_families[family]["orders"] if order["invoice_id"] == invoice_id),
                    None
                )

                if invoice_exists:
                    # Append warehouse details to existing invoice
                    invoice_exists["warehouses"].append(warehouse)
                else:
                    # Create new invoice entry
                    grouped_families[family]["orders"].append({
                        "invoice_id": invoice_id,
                        "invoice": invoice,
                        "cod_amount":cod_amount,
                        "box_count": box_count,
                        "warehouses": [warehouse]
                    })
                    
            # Convert dictionary to list format
            formatted_response = list(grouped_families.values())
            return Response({"results": formatted_response}, status=status.HTTP_200_OK)   

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CategoryWiseProductCountDateView(BaseTokenView):

    def get(self, request, date):
        try:
            user = self.get_user_from_token(request)

            if not user:
                return Response(
                    {"status": "error", "message": "Unauthorized"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Convert string date -> Date object
            try:
                selected_date = datetime.strptime(date, "%Y-%m-%d").date()
            except ValueError:
                return Response(
                    {"status": "error", "message": "Invalid date format. Use YYYY-MM-DD"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            category_data = (
                Warehousedata.objects.filter(postoffice_date=selected_date)
                .annotate(
                    category_name=Coalesce(
                        "order__items__product__product_category__category_name",
                        Value("Uncategorized")
                    )
                )
                .values("category_name")
                .annotate(total_quantity=Sum("order__items__quantity"))
                .order_by("-total_quantity")
            )

            result = []
            for row in category_data:
                result.append({
                    "category": row["category_name"],
                    "total_quantity": row["total_quantity"] or 0
                })

            return Response(
                {
                    "status": "success",
                    "postoffice_date": str(selected_date),
                    "category_wise_products": result
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OrderListByMonthView(APIView):
    def get(self, request, year, month):
        try:
            # Format month to 2 digits (e.g., 7 → 07)
            month_str = str(month).zfill(2)
            year_str = str(year)

            # Filter based on order_date string starting with "YYYY-MM"
            orders = Order.objects.filter(order_date__startswith=f"{year_str}-{month_str}").exclude(family__name="bepocart").order_by('-id')

            if not orders.exists():
                return Response(
                    {"status": "error", "message": "No orders found for this month"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = OrderMonthSerializer(orders, many=True)
            return Response({"status": "success", "results": serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WarehouseUpdateCheckedByView(BaseTokenView):
    def put(self, request, shipped_date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Get the checked_by user ID from request data
            checked_by_id = request.data.get("checked_by")
            if not checked_by_id:
                return Response(
                    {"status": "error", "message": "checked_by user ID is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate if the user exists
            try:
                checked_by_user = User.objects.get(id=checked_by_id)
            except User.DoesNotExist:
                return Response(
                    {"status": "error", "message": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Fetch and update all warehouse records matching shipped_date
            warehouses = Warehousedata.objects.filter(shipped_date=shipped_date)
            if not warehouses.exists():
                return Response(
                    {"status": "error", "message": "No warehouse data found for the given shipped date"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            warehouses.update(checked_by=checked_by_user)
            
            # Retrieve and sort warehouses by shipped_date
            sorted_warehouses = Warehousedata.objects.filter(shipped_date=shipped_date).order_by("shipped_date")
            serializer = WarehousedataSerializer(sorted_warehouses, many=True)
            
            return Response(
                {"status": "success", "message": "Checked by updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )
        
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ExpenseDetailView(BaseTokenView):
    def get(self, request, id, *args, **kwargs):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch expense or return 404
            expense = get_object_or_404(ExpenseModel, id=id)

            # Serialize
            serializer = ExpenseGetSerializer(expense)

            return Response({
                "status": "success",
                "message": "Expense retrieved successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ExpensAddView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response


            expense = ExpenseSerializer(data=request.data)

            if expense.is_valid():

                expense_obj = expense.save()

                return Response({
                    "status": "success",
                    "message": "Expense Added Successfully",
                    "data": expense.data
                }, status=status.HTTP_200_OK)

            return Response(expense.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense_data = ExpenseModel.objects.all().order_by('-id')
            serializer = ExpenseModelsSerializers(expense_data, many=True)
            # Add category_id to each expense
            expenses_with_category = []
            for expense, serialized in zip(expense_data, serializer.data):
                item = dict(serialized)
                item['category_id'] = getattr(expense, 'category_id', None)
                expenses_with_category.append(item)
            return Response({"data": expenses_with_category}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExpensAddGETView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()
            purpose = request.GET.get("purpose", "").strip()
            purpose_id = request.GET.get("purpose_id", "").strip()
            expense_type = request.GET.get("expense_type", "").strip()
            company = request.GET.get("company", "").strip()
            company_id = request.GET.get("company_id", "").strip()
            bank = request.GET.get("bank", "").strip()
            bank_id = request.GET.get("bank_id", "").strip()
            added_by = request.GET.get("added_by", "").strip()
            category_id = request.GET.get("category_id", "").strip()
            asset_types = request.GET.get("asset_types", "").strip()
            min_amount = request.GET.get("min_amount", "").strip()
            max_amount = request.GET.get("max_amount", "").strip()
            ordering = request.GET.get("ordering", "-id").strip()

            expense_data = ExpenseModel.objects.select_related(
                "company",
                "payed_by",
                "bank",
                "category",
                "purpose_of_payment",
                "loan",
            ).all()

            # Search
            if search:
                expense_data = expense_data.filter(
                    Q(company__name__icontains=search) |
                    Q(bank__name__icontains=search) |
                    Q(payed_by__name__icontains=search) |
                    Q(purpose_of_payment__name__icontains=search) |
                    Q(description__icontains=search) |
                    Q(transaction_id__icontains=search) |
                    Q(added_by__icontains=search) |
                    Q(name__icontains=search) |
                    Q(expense_type__icontains=search) |
                    Q(amount__icontains=search)
                )

            # Date filters
            if start_date:
                parsed_start_date = parse_date(start_date)
                if parsed_start_date:
                    expense_data = expense_data.filter(expense_date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if parsed_end_date:
                    expense_data = expense_data.filter(expense_date__lte=parsed_end_date)

            # Purpose filters
            if purpose_id:
                expense_data = expense_data.filter(purpose_of_payment_id=purpose_id)

            if purpose:
                expense_data = expense_data.filter(
                    purpose_of_payment__name__icontains=purpose
                )

            # Expense type
            if expense_type:
                expense_type = expense_type.strip().lower()
                known_types = {"miscellaneous", "permanent", "emi", "cargo", "purchase"}

                if expense_type == "others":
                    expense_data = expense_data.filter(
                        Q(expense_type__isnull=True) |
                        Q(expense_type__exact="") |
                        ~Q(expense_type__in=list(known_types))
                    )
                else:
                    expense_data = expense_data.filter(expense_type__iexact=expense_type)

            # Company filters
            if company_id:
                expense_data = expense_data.filter(company_id=company_id)

            if company:
                expense_data = expense_data.filter(company__name__icontains=company)

            # Bank filters
            if bank_id:
                expense_data = expense_data.filter(bank_id=bank_id)

            if bank:
                expense_data = expense_data.filter(bank__name__icontains=bank)

            # Added by
            if added_by:
                expense_data = expense_data.filter(added_by__icontains=added_by)

            # Category
            if category_id:
                expense_data = expense_data.filter(category_id=category_id)

            # Asset type
            if asset_types:
                expense_data = expense_data.filter(asset_types__iexact=asset_types)

            # Amount range
            if min_amount:
                try:
                    expense_data = expense_data.filter(amount__gte=Decimal(min_amount))
                except (InvalidOperation, ValueError):
                    pass

            if max_amount:
                try:
                    expense_data = expense_data.filter(amount__lte=Decimal(max_amount))
                except (InvalidOperation, ValueError):
                    pass

            # Safe ordering
            allowed_ordering_fields = [
                "id", "-id",
                "expense_date", "-expense_date",
                "amount", "-amount",
                "expense_type", "-expense_type",
                "added_by", "-added_by",
            ]
            if ordering not in allowed_ordering_fields:
                ordering = "-id"

            expense_data = expense_data.order_by(ordering)

            # Overall summary on FULL FILTERED queryset
            overall_summary = expense_data.aggregate(
                total_count=Count("id"),
                total_amount=Coalesce(Sum("amount"), Decimal("0.00"))
            )

            # Summary by expense_type on FULL FILTERED queryset
            type_rows = (
                expense_data
                .values("expense_type")
                .annotate(
                    count=Count("id"),
                    amount=Coalesce(Sum("amount"), Decimal("0.00"))
                )
                .order_by("expense_type")
            )

            summary_map = {
                "miscellaneous": {"count": 0, "amount": "0.00"},
                "permanent": {"count": 0, "amount": "0.00"},
                "emi": {"count": 0, "amount": "0.00"},
                "cargo": {"count": 0, "amount": "0.00"},
                "purchase": {"count": 0, "amount": "0.00"},
                "others": {"count": 0, "amount": "0.00"},
            }

            known_types = {"miscellaneous", "permanent", "emi", "cargo", "purchase"}

            for row in type_rows:
                raw_type = (row.get("expense_type") or "").strip().lower()
                key = raw_type if raw_type in known_types else "others"

                summary_map[key]["count"] += row["count"]
                summary_map[key]["amount"] = str(
                    Decimal(summary_map[key]["amount"]) + (row["amount"] or Decimal("0.00"))
                )

            paginator = StandardPagination()
            page = paginator.paginate_queryset(expense_data, request)
            serializer = ExpenseModelsSerializers(page, many=True)

            expenses_with_ids = []
            for expense, serialized in zip(page, serializer.data):
                item = dict(serialized)
                item["category_id"] = expense.category_id if expense.category_id else None
                item["purpose_id"] = expense.purpose_of_payment_id if expense.purpose_of_payment_id else None
                item["company_id"] = expense.company_id if expense.company_id else None
                item["bank_id"] = expense.bank_id if expense.bank_id else None
                expenses_with_ids.append(item)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Expenses fetched successfully",
                "filters": {
                    "search": search,
                    "start_date": start_date,
                    "end_date": end_date,
                    "purpose": purpose,
                    "purpose_id": purpose_id,
                    "expense_type": expense_type,
                    "company": company,
                    "company_id": company_id,
                    "bank": bank,
                    "bank_id": bank_id,
                    "added_by": added_by,
                    "category_id": category_id,
                    "asset_types": asset_types,
                    "min_amount": min_amount,
                    "max_amount": max_amount,
                    "ordering": ordering,
                },
                "summary": {
                    "total_count": overall_summary["total_count"],
                    "total_amount": str(overall_summary["total_amount"]),
                },
                "summary_by_type": summary_map,
                "results": expenses_with_ids
            })

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class ExpenseFilteredGETView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()
            purpose = request.GET.get("purpose", "").strip()
            purpose_id = request.GET.get("purpose_id", "").strip()
            expense_type = request.GET.get("expense_type", "").strip()
            company = request.GET.get("company", "").strip()
            company_id = request.GET.get("company_id", "").strip()
            bank = request.GET.get("bank", "").strip()
            bank_id = request.GET.get("bank_id", "").strip()
            added_by = request.GET.get("added_by", "").strip()
            category_id = request.GET.get("category_id", "").strip()
            asset_types = request.GET.get("asset_types", "").strip()
            min_amount = request.GET.get("min_amount", "").strip()
            max_amount = request.GET.get("max_amount", "").strip()
            ordering = request.GET.get("ordering", "-id").strip()

            expense_data = ExpenseModel.objects.select_related(
                "company",
                "payed_by",
                "bank",
                "category",
                "purpose_of_payment",
                "loan",
            ).all()

            if search:
                expense_data = expense_data.filter(
                    Q(company__name__icontains=search) |
                    Q(bank__name__icontains=search) |
                    Q(payed_by__name__icontains=search) |
                    Q(purpose_of_payment__name__icontains=search) |
                    Q(description__icontains=search) |
                    Q(transaction_id__icontains=search) |
                    Q(added_by__icontains=search) |
                    Q(name__icontains=search) |
                    Q(expense_type__icontains=search) |
                    Q(amount__icontains=search)
                )

            if start_date:
                parsed_start_date = parse_date(start_date)
                if parsed_start_date:
                    expense_data = expense_data.filter(expense_date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if parsed_end_date:
                    expense_data = expense_data.filter(expense_date__lte=parsed_end_date)

            if purpose_id:
                expense_data = expense_data.filter(purpose_of_payment_id=purpose_id)

            if purpose:
                expense_data = expense_data.filter(
                    purpose_of_payment__name__icontains=purpose
                )

            if expense_type:
                expense_data = expense_data.filter(expense_type__iexact=expense_type)

            if company_id:
                expense_data = expense_data.filter(company_id=company_id)

            if company:
                expense_data = expense_data.filter(company__name__icontains=company)

            if bank_id:
                expense_data = expense_data.filter(bank_id=bank_id)

            if bank:
                expense_data = expense_data.filter(bank__name__icontains=bank)

            if added_by:
                expense_data = expense_data.filter(added_by__icontains=added_by)

            if category_id:
                expense_data = expense_data.filter(category_id=category_id)

            if asset_types:
                expense_data = expense_data.filter(asset_types__iexact=asset_types)

            if min_amount:
                try:
                    expense_data = expense_data.filter(amount__gte=Decimal(min_amount))
                except (InvalidOperation, ValueError):
                    pass

            if max_amount:
                try:
                    expense_data = expense_data.filter(amount__lte=Decimal(max_amount))
                except (InvalidOperation, ValueError):
                    pass

            allowed_ordering_fields = [
                "id", "-id",
                "expense_date", "-expense_date",
                "amount", "-amount",
                "expense_type", "-expense_type",
                "added_by", "-added_by",
            ]
            if ordering not in allowed_ordering_fields:
                ordering = "-id"

            expense_data = expense_data.order_by(ordering)

            overall_summary = expense_data.aggregate(
                total_count=Count("id"),
                total_amount=Coalesce(Sum("amount"), Decimal("0.00"))
            )

            serializer = ExpenseModelsSerializers(expense_data, many=True)

            expenses_with_ids = []
            for expense, serialized in zip(expense_data, serializer.data):
                item = dict(serialized)
                item["category_id"] = expense.category_id if expense.category_id else None
                item["purpose_id"] = expense.purpose_of_payment_id if expense.purpose_of_payment_id else None
                item["company_id"] = expense.company_id if expense.company_id else None
                item["bank_id"] = expense.bank_id if expense.bank_id else None
                expenses_with_ids.append(item)

            return Response(
                {
                    "status": "success",
                    "message": "Filtered expenses fetched successfully",
                    "filters": {
                        "search": search,
                        "start_date": start_date,
                        "end_date": end_date,
                        "purpose": purpose,
                        "purpose_id": purpose_id,
                        "expense_type": expense_type,
                        "company": company,
                        "company_id": company_id,
                        "bank": bank,
                        "bank_id": bank_id,
                        "added_by": added_by,
                        "category_id": category_id,
                        "asset_types": asset_types,
                        "min_amount": min_amount,
                        "max_amount": max_amount,
                        "ordering": ordering,
                    },
                    "summary": {
                        "total_count": overall_summary["total_count"],
                        "total_amount": str(overall_summary["total_amount"]),
                    },
                    "results": expenses_with_ids
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class ExpenseDashboardSummaryView(BaseTokenView):

    def get(self, request):
        try:
            # Token validation
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            today = date.today()
            month_start = today.replace(day=1)

            # Month-to-date grouped summary
            mtd_qs = (
                ExpenseModel.objects
                .filter(
                    expense_date__gte=month_start,
                    expense_date__lte=today
                )
                .values("expense_type")
                .annotate(total=Sum("amount"))
                .order_by("expense_type")
            )

            summary = []
            mtd_total = 0.0

            for row in mtd_qs:
                total = float(row.get("total") or 0)
                summary.append({
                    "expense_type": row.get("expense_type"),
                    "total": round(total, 2)
                })
                mtd_total += total

            # All-time grand total
            all_time_total = (
                ExpenseModel.objects
                .aggregate(total=Sum("amount"))
                .get("total") or 0
            )

            return Response({
                "range": {
                    "from": month_start,
                    "to": today
                },
                "summary": summary,
                "month_total": round(mtd_total, 2),
                "all_time_total": round(float(all_time_total), 2)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


  
class ExpensAddViewExpectEmi(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense=ExpenseExpectEmiSerializer(data=request.data)
            if expense.is_valid():
                expense.save()
                return Response({"status": "success", "message": "Expense Added Successfully","data":expense.data}, status=status.HTTP_200_OK)
            return Response(expense.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExpensAddViewExpectEmiUpdate(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense=get_object_or_404(ExpenseModel,pk=pk)
            serializer = ExpenseExpectEmiSerializer(expense, data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Expense Updated Successfully"}, status=status.HTTP_200_OK)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                            
           
        

class ExpensAddAssestView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense=ExpenseSerializerAssest(data=request.data)
            if expense.is_valid():
                expense.save()
                return Response({"status": "success", "message": "Expense Added Successfully","data":expense.data},status=status.HTTP_200_OK)
            return Response(expense.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    def put(self,request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense_change=ExpenseModel.objects.get(pk=pk)
            expense=ExpenseSerializerAssest(expense_change,data=request.data,partial=True)
            if expense.is_valid():
                saved_expense=expense.save()
                return Response({"status": "success", "message": "Expense Updated Successfully"}, status=status.HTTP_200_OK)
            return Response(expense.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        
class ExpenseUpdate(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            expense=get_object_or_404(ExpenseModel,pk=pk)
            serializer = ExpenseSerializer(expense, data=request.data,partial=True)
            if serializer.is_valid():
                updated_instance = serializer.save()
                return Response({"status": "success", "message": "Expense Updated Successfully"}, status=status.HTTP_200_OK)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                            
        


class GRVaddView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            logger.info("Incoming data: %s", request.data)

            # accept list or single object
            payload = request.data if isinstance(request.data, list) else [request.data]

            ser = GRVModelSerializer(data=payload, many=True)
            if ser.is_valid():
                ser.save()
                logger.info("Serialized data (after save): %s", ser.data)
                return Response(
                    {"status": "success", "message": "Added successfully", "data": ser.data},
                    status=status.HTTP_201_CREATED
                )

            logger.error("Validation failed: %s", ser.errors)
            return Response(
                {"status": "error", "message": "Validation failed", "errors": ser.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.exception("Error occurred in GRVaddView")
            return Response(
                {"status": "error", "message": "An error occurred while processing the request", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def get(self,request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
           
            grvdata = GRVModel.objects.all().order_by('-id')

            if not grvdata.exists():
                return Response(
                    {"status": "error", "message": "No GRV records found for this staff."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Serialize the GRV data
            serializer = GRVSerializer(grvdata, many=True)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
          
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class GRVGetViewById(BaseTokenView):
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            grvs=GRVModel.objects.get(pk=pk)
            serializer = GRVModelSerializer(grvs)
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

from collections import defaultdict

def _norm_usability(v):
    v = (v or "").strip().lower()
    return v if v else "usable"

def _norm_id(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v

def _as_int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0

def _qty_from_row(row):
    for k in ("quantity", "qty", "rack_quantity", "rack_stock"):
        if k in row:
            return max(_as_int(row.get(k)), 0)
    return 0

def _key_tuple(row):
    return (
        _norm_id(row.get("rack_id")),
        (row.get("column_name") or "").strip(),
        _norm_usability(row.get("usability")),
    )

def _coalesce(rows, sign):
    acc = defaultdict(int)
    for r in rows or []:
        q = _qty_from_row(r)
        if q > 0:
            acc[_key_tuple(r)] += sign * q
    return acc

def _apply_rack_deltas_on_locked_product(p, *, add_rows=None, sub_rows=None, debug=False):
    """
    Mutates p.rack_details in-memory (p is already locked/selected_for_update()):

      + add_rows (e.g., GRV.rack_details)
      - sub_rows (e.g., GRV.selected_racks)

    Creates missing slots for positive nets; validates negatives; saves once.
    """
    add_rows = add_rows or []
    sub_rows = sub_rows or []

    adds = _coalesce(add_rows, +1)
    subs = _coalesce(sub_rows, -1)

    net = defaultdict(int)
    for k, v in adds.items():
        net[k] += v
    for k, v in subs.items():
        net[k] += v  # negative

    if debug:
        print("ADDs:", dict(adds))
        print("SUBs:", dict(subs))
        print("NET :", dict(net))

    if not net:
        return

    racks = list(p.rack_details or [])
    index = {
        (_norm_id(r.get("rack_id")), (r.get("column_name") or "").strip(), _norm_usability(r.get("usability"))): r
        for r in racks
    }

    # Create slots for +ve deltas
    for key, d in net.items():
        if d > 0 and key not in index:
            rack_id, col, usability = key
            slot = {
                "warehouse": None,
                "rack_id": rack_id,
                "rack_name": None,
                "column_name": col,
                "usability": usability,
                "rack_stock": 0,
                "rack_lock": 0,
            }
            racks.append(slot)
            index[key] = slot
            if debug:
                print(f"[CREATE] {key}")

    # Validate negatives
    for key, d in net.items():
        if d >= 0:
            continue
        slot = index.get(key)
        if not slot:
            raise ValueError(f"Rack not found for key={key} (cannot subtract).")
        cur = _as_int(slot.get("rack_stock"))
        if cur + d < 0:
            raise ValueError(f"Insufficient stock in rack {key}: have {cur}, need {-d}.")

    # Apply net
    changed = False
    for key, d in net.items():
        if d == 0:
            continue
        slot = index.get(key)
        if not slot:
            continue
        before = _as_int(slot.get("rack_stock"))
        slot["rack_stock"] = before + d
        changed = True
        if debug:
            action = "ADD" if d > 0 else "SUB"
            print(f"[{action}] {key}: {before} -> {slot['rack_stock']}")

    if changed:
        p.rack_details = racks
        # Single save -> your Products.save() will recompute stock/damaged/partial
        p.save(update_fields=["rack_details"])



class GRVUpdateView(BaseTokenView):      
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            grv = get_object_or_404(GRVModel, pk=pk)
            old_status = (grv.status or "").lower()

            serializer = GRVModelSerializer(grv, data=request.data, partial=True)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            with transaction.atomic():
                serializer.save()
                grv.refresh_from_db()

                remark = (grv.remark or "").strip().lower()
                new_status = (grv.status or "").lower()

                if remark in ("return", "exchange", "cod_return") and old_status != "approved" and new_status == "approved":
                    if not grv.product_id:
                        raise ValidationError("No product linked to this GRV.")

                    # Lock the product ONCE
                    p = Products.objects.select_for_update().get(pk=grv.product_id_id)

                    # Net: +rack_details, -selected_racks (set debug=True if needed)
                    _apply_rack_deltas_on_locked_product(
                        p,
                        add_rows=grv.rack_details or [],
                        sub_rows=grv.selected_racks or [],
                        debug=False,  # flip to True to print adds/subs/net
                    )

            return Response({"status": "success", "message": "GRV updated successfully"}, status=status.HTTP_200_OK)

        except ValueError as ve:
            return Response({"status": "error", "message": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as ve:
            return Response({"status": "error", "message": ve.detail if hasattr(ve, "detail") else str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class SalesReportView(BaseTokenView):
    def get(self, request):
        try:
            # Authenticate the user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch all orders
            orders = Order.objects.all()

            # Approved statuses
            approved_statuses = [
                'Approved',
                'Shipped',
                'Invoice Created',
                'Invoice Approved',
                'Waiting For Confirmation',
                'Invoice Rejected',
                'To Print',
                'Processing',
                'Completed'
            ]

            # Get distinct order dates in descending order
            distinct_dates = orders.order_by('-order_date').values_list('order_date', flat=True).distinct()

            report_data = []

            for date in distinct_dates:
                daily_orders = orders.filter(order_date=date)
                total_amount = daily_orders.aggregate(total=Sum('total_amount'))['total'] or 0
                total_bills = daily_orders.count()

                # Approved
                approved_bills = daily_orders.filter(status__in=approved_statuses)
                approved_count = approved_bills.count()
                approved_amount = approved_bills.aggregate(total=Sum('total_amount'))['total'] or 0

                # Rejected
                rejected_bills = daily_orders.exclude(status__in=approved_statuses)
                rejected_count = rejected_bills.count()
                rejected_amount = rejected_bills.aggregate(total=Sum('total_amount'))['total'] or 0

                # Order details
                order_details = daily_orders.values(
                    'id',
                    'invoice',
                    'order_date',
                    'status',
                    'total_amount',
                    'customer__name',
                    'manage_staff__name',
                    'company__name',
                    'state__name',
                    'family__name'
                )

                report_data.append({
                    "date": date,
                    "total_bills_in_date": total_bills,
                    "amount": total_amount,
                    "approved": {
                        "bills": approved_count,
                        "amount": approved_amount,
                    },
                    "rejected": {
                        "bills": rejected_count,
                        "amount": rejected_amount,
                    },
                    "order_details": list(order_details),
                })

            return Response({"sales_report": report_data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

class InvoiceReportView(BaseTokenView):
    def get(self, request, date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Parse and validate the date
            date = parse_date(date)
            if not date:
                return Response(
                    {"status": "error", "message": "Invalid date format. Use YYYY-MM-DD."},
                    status=400
                )

            # Filter orders for the given date
            orders = Order.objects.filter(order_date=date)
            total_bills = orders.count()
            total_amount = orders.aggregate(Sum('total_amount'))['total_amount__sum'] or 0

            # Get staff details and their order counts
            staff_ids = orders.values_list('manage_staff', flat=True).distinct()
            staff_details = User.objects.filter(id__in=staff_ids)

            staff_info = []
            for staff in staff_details:
                # Fetch total orders handled by this staff
                staff_orders = orders.filter(manage_staff=staff)
                staff_total_bills = staff_orders.count()
                staff_total_amount = staff_orders.aggregate(Sum('total_amount'))['total_amount__sum'] or 0

                # Collect detailed information for all orders handled by this staff
                staff_orders_details = []
                for order in staff_orders:
                    try:
                        staff_orders_details.append({
                            'invoice': order.invoice,
                            'status': order.status,
                            'company': order.company.name if order.company else None,
                            'customer': order.customer.name if order.customer else None,
                            'state': order.state.name if order.state else None,
                            'total_amount': order.total_amount,
                            'order_date': order.order_date,
                            'family_name': order.family.name if order.family else None
                        })
                    except AttributeError as e:
                        raise

                staff_info.append({
                    'id': staff.pk,
                    'name': staff.name,
                    'family': staff.family.name if staff.family else None,
                    'total_bills': staff_total_bills,
                    'total_amount': staff_total_amount,
                    'orders_details': staff_orders_details
                })

            return Response({
                "status": "success",
              
                "data": staff_info,
            })

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=500)



        
class BillsView(BaseTokenView):
    def get(self,request,pk,date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            order_list=Order.objects.filter(order_date = date, manage_staff = pk)
            serializer = OrderSerializer(order_list, many=True)
            return Response({"data":serializer.data})
          

        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CreditSalesReportView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response  
            
            orders = Order.objects.filter(payment_status="credit")
            
            grouped_orders = defaultdict(list)
            for order in orders:
                grouped_orders[order.order_date].append(order)

            # Sort the grouped_orders by date descending
            sorted_dates = sorted(grouped_orders.keys(), reverse=True)

            response_data = []
            for date in sorted_dates:
                orders_list = grouped_orders[date]
                date_data = []
                for order in orders_list:
                    total_paid_amount = PaymentReceipt.objects.filter(order=order).aggregate(
                    total_paid=Sum(Cast('amount', FloatField()))
                    )['total_paid'] or 0.0
                     
                    total_paid_amount = float(total_paid_amount)
                    order_total_amount = float(order.total_amount)  
                    balance_amount = order_total_amount - total_paid_amount
                    
                    serializer = OrderDetailSerializer(order)
                    order_data = serializer.data
                    order_data['balance_amount'] = balance_amount  # Optional: Include balance
                    
                    date_data.append(order_data)
                
                response_data.append({
                    "date": date,
                    "orders": date_data
                })
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        except Order.DoesNotExist:
            return Response({"error": "No orders found with 'credit' payment status."}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class CreditBillsView(BaseTokenView):
    def get(self,request,date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            order_list=Order.objects.filter(order_date =date,payment_status="credit")
            serializer = OrderPaymentSerializer(order_list, many=True)
            return Response({"data":serializer.data})
          

        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class CODSalesReportView(BaseTokenView):
    
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response  
            orders = Order.objects.filter(payment_status="COD").order_by('-order_date')
            
            grouped_orders = defaultdict(list)
            for order in orders:
                grouped_orders[order.order_date].append(order)
            
            # Prepare the response data
            response_data = []
            for date, orders_list in grouped_orders.items():
                date_data = []
                for order in orders_list:
                    # Get total paid amount for the current order
                    total_paid_amount = PaymentReceipt.objects.filter(order=order).aggregate(
                    total_paid=Sum(Cast('amount', FloatField()))
                    )['total_paid'] or 0.0
                    
                    # Convert total_paid_amount to float if it's a string
                    total_paid_amount = float(total_paid_amount)
                    
                    # Calculate the balance amount (order_total_amount - total_paid_amount)
                    order_total_amount = float(order.total_amount)  # Assuming 'total_amount' is a field on the Order model
                    balance_amount = order_total_amount - total_paid_amount
                    
                    # Serialize the order and add total paid and balance amount
                    serializer = OrderDetailSerializer(order)
                    order_data = serializer.data
                    order_data['total_paid_amount'] = total_paid_amount
                    order_data['balance_amount'] = balance_amount
                    
                    date_data.append(order_data)
                
                response_data.append({
                    "date": date,
                    "orders": date_data
                })
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        except Order.DoesNotExist:
            return Response({"error": "No orders found with 'credit' payment status."}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        


class CODBillsView(BaseTokenView):
    def get(self,request,date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            order_list=Order.objects.filter(order_date =date,payment_status="COD")
            serializer = OrderPaymentSerializer(order_list, many=True)
            return Response({"data":serializer.data})
          

        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                

class ProductSalesReportView(APIView):
    def get(self, request):
        try:
            # Fetch all order items with related product and order details
            order_items = OrderItem.objects.select_related('product', 'order').all()

            if not order_items.exists():
                return Response(
                    {"error": "No records found."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Group order items by date and product
            grouped_data = defaultdict(lambda: defaultdict(list))

            for item in order_items:
                # Parse order_date
                date = item.order.order_date
                formatted_date = (
                    date if isinstance(date, str) else date.strftime('%Y-%m-%d')
                )

                product_name = item.product.name

                # Serialize individual order items
                serializer = ProductSalesReportSerializer(item)
                grouped_data[formatted_date][product_name].append(serializer.data)

            # Fetch remaining stock directly from the Products model
            product_stock = {
                product.name: product.stock for product in Products.objects.all()
            }

            # Format the final response (latest date first)
            formatted_response = []
            for date in sorted(grouped_data.keys(), reverse=True):  # Sort dates descending
                products = grouped_data[date]
                for product, data in products.items():
                    formatted_response.append({
                        "date": date,
                        "product": product,
                        "stock": product_stock.get(product, 0),  # Attach stock from Products model
                        "data": data
                    })

            return Response(formatted_response, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )    


        


class CategoryWiseProductCountView(APIView):
    def get(self, request):
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        if not start_date or not end_date:
            return Response(
                {
                    "status": "error",
                    "message": "start_date and end_date are required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # validate incoming format only
            datetime.strptime(start_date, "%Y-%m-%d")
            datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            return Response(
                {
                    "status": "error",
                    "message": "Invalid date format. Use YYYY-MM-DD"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = (
            OrderItem.objects.filter(
                order__order_date__gte=start_date,
                order__order_date__lte=end_date
            )
            .values(
                "product__product_category__id",
                "product__product_category__category_name"
            )
            .annotate(count=Sum("quantity"))
            .order_by("product__product_category__category_name")
        )

        data = [
            {
                "category_id": item["product__product_category__id"],
                "category_name": item["product__product_category__category_name"] or "Uncategorized",
                "count": item["count"] or 0,
            }
            for item in queryset
        ]

        return Response(
            {
                "status": "success",
                "message": "Category-wise product count fetched successfully",
                "start_date": start_date,
                "end_date": end_date,
                "data": data
            },
            status=status.HTTP_200_OK
        )




class ProductCountByCategoryView(APIView):
    def get(self, request):
        category_id = request.GET.get("category_id")
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        if not category_id:
            return Response(
                {"status": "error", "message": "category_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not start_date or not end_date:
            return Response(
                {"status": "error", "message": "start_date and end_date are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # NOTE:
        # Since order_date is CharField in your model,
        # this works correctly only if order_date is stored as YYYY-MM-DD format.
        queryset = OrderItem.objects.filter(
            product__product_category_id=category_id,
            order__order_date__range=[start_date, end_date]
        ).select_related("product", "order")

        if not queryset.exists():
            return Response({
                "status": "success",
                "message": "No data found",
                "count": 0,
                "data": []
            }, status=status.HTTP_200_OK)

        grouped_data = queryset.values(
            "product__id",
            "product__name",
            "product__product_category__id",
            "product__product_category__category_name",
        ).annotate(
            total_quantity=Sum("quantity"),
            order_item_count=Count("id")
        ).order_by("product__name")

        result = []

        for item in grouped_data:
            product_id = item["product__id"]

            invoice_list = list(
                queryset.filter(product_id=product_id)
                .values("order__id", "order__invoice")
                .distinct()
            )

            result.append({
                "product_id": item["product__id"],
                "product_name": item["product__name"],
                "category_id": item["product__product_category__id"],
                "category_name": item["product__product_category__category_name"],
                "total_quantity": item["total_quantity"] or 0,
                "order_item_count": item["order_item_count"] or 0,
                "invoices": invoice_list,
            })

        return Response({
            "status": "success",
            "message": "Product count with invoices fetched successfully",
            "count": len(result),
            "filters": {
                "category_id": category_id,
                "start_date": start_date,
                "end_date": end_date,
            },
            "data": result
        }, status=status.HTTP_200_OK)



class StatewiseSalesReport(APIView):
    def get(self, request):
        try:
            states = State.objects.all()
            data = []

            for state in states:
                # Get orders grouped by order_date for the state
                orders_by_date = Order.objects.filter(state=state).values('order_date').distinct()

                # Calculating counts and total amounts for each status
                total_orders = Order.objects.filter(state=state).count()
                total_amount = Order.objects.filter(state=state).aggregate(total=Sum('total_amount'))['total'] or 0

                approved_orders = Order.objects.filter(state=state, status='Approved').count()
                approved_amount = Order.objects.filter(state=state, status='Approved').aggregate(total=Sum('total_amount'))['total'] or 0

                shipped_orders = Order.objects.filter(state=state, status='Completed').count()
                shipped_amount = Order.objects.filter(state=state, status='Completed').aggregate(total=Sum('total_amount'))['total'] or 0

                cancelled_orders = Order.objects.filter(state=state, status='Cancelled').count()
                cancelled_amount = Order.objects.filter(state=state, status='Cancelled').aggregate(total=Sum('total_amount'))['total'] or 0

                rejected_orders = Order.objects.filter(state=state, status='Rejected').count()
                rejected_amount = Order.objects.filter(state=state, status='Rejected').aggregate(total=Sum('total_amount'))['total'] or 0

                returned_orders = Order.objects.filter(state=state, status='Return').count()
                returned_amount = Order.objects.filter(state=state, status='Return').aggregate(total=Sum('total_amount'))['total'] or 0

                state_data = {
                    'id': state.pk,
                    'name': state.name,
                    'total_orders_count': total_orders,
                    'total_amount': total_amount,
                    'approved_orders_count': approved_orders,
                    'approved_amount': approved_amount,
                    'completed_orders_count': shipped_orders,
                    'completed_amount': shipped_amount,
                    'cancelled_orders_count': cancelled_orders,
                    'cancelled_amount': cancelled_amount,
                    'rejected_orders_count': rejected_orders,
                    'rejected_amount': rejected_amount,
                    'returned_orders_count': returned_orders,
                    'returned_amount': returned_amount,
                    'orders': []
                }

                for order_date in orders_by_date:
                    date_orders = Order.objects.filter(state=state, order_date=order_date['order_date'])
                    order_data = {
                        'order_date': order_date['order_date'],
                        'waiting_orders': OrderStateWiseSerializer(date_orders, many=True).data
                    }
                    state_data['orders'].append(order_data)

                data.append(state_data)

            return Response({"data": data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class StateOrderDetailsView(BaseTokenView):
    def get(self, request, state_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

           
            state = State.objects.get(pk=state_id)
            
            orders = Order.objects.filter(state=state)

            serializer = OrderDetailSerializer(orders, many=True)

           
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)

        except State.DoesNotExist:
            return Response({"status": "error", "message": "State not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
          
            return JsonResponse({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  
        
class DeliveryListView(BaseTokenView):
    def get(self, request, date):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            data = Warehousedata.objects.filter(shipped_date=date)
            serializer = WareHouseSerializer(data, many=True)
            # Add order_id to each warehouse entry
            warehouse_with_order_id = []
            for obj, serialized in zip(data, serializer.data):
                item = dict(serialized)
                item['order_id'] = getattr(obj.order, 'id', None) if hasattr(obj, 'order') and obj.order else None
                warehouse_with_order_id.append(item)
            return Response({"data": warehouse_with_order_id}, status=status.HTTP_200_OK)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ParcalServiceView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            serializer = ParcalSerializers(data = request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Parcal saved successfully"}, status=status.HTTP_200_OK)
            return Response({"status":"error","message":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def get(self, request):
        try:
            parcal = ParcalService.objects.all()
            serializer = ParcalSerializers(parcal, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
        
class EditParcalService(APIView):
    def put(self, request, pk):
        try:
            parcal = ParcalService.objects.get(pk=pk)
            serializer = ParcalSerializers(parcal, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Parcal updated successfully"}, status=status.HTTP_200_OK)
            return Response({"status": "error", "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e :
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class ProductBulkUploadAPIView(BaseTokenView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        
        authUser, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response
            
            
        # Check if file is provided
        if 'file' not in request.FILES:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Read the file based on its type (CSV or Excel)
        excel_file = request.FILES['file']
        try:
            file_extension = os.path.splitext(excel_file.name)[1].lower()
            
            if file_extension == '.csv':
                df = pd.read_csv(excel_file)  # Handle CSV files
            elif file_extension in ['.xlsx', '.xls']:
                df = pd.read_excel(excel_file, engine='openpyxl')  # Handle Excel files
            else:
                return Response({"error": "Unsupported file format. Please upload a CSV or Excel file."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"Error reading the file: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the expected columns are in the file
        required_columns = ['name','hsn_code','family','warehouse','type','unit','purchase_rate','tax','image','selling_price','landing_cost','retail_price','stock','color','size','groupID','PURCHASE_TYPES','STATUS_TYPES']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            return Response({"error": f"Missing columns: {', '.join(missing_columns)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Process and save the data to the database
        products_data = []
        for _, row in df.iterrows():
            try:

                # Retrieve or create the family objects
                family_names = str(row['family']).split(',')
                families = []
                for fam_name in family_names:
                    fam, _ = Family.objects.get_or_create(name=fam_name.strip())  # Ensures family exists
                    families.append(fam)

                warehouse = None
                if pd.notna(row['warehouse']):  # Ensure warehouse ID is not empty
                    try:
                        warehouse = WareHouse.objects.get(id=int(row['warehouse']))  # Convert ID to integer
                    except WareHouse.DoesNotExist:
                        return Response({"error": f"Warehouse ID {row['warehouse']} not found"}, status=status.HTTP_400_BAD_REQUEST)

                # Create product instance    
               

                # Create product instance
                product = Products(
                    name=row['name'],
                    hsn_code=row['hsn_code'],
                   
                    type=row['type'],
                    unit=row['unit'],
                    purchase_rate=row['purchase_rate'],
                    tax=row['tax'],
                    # image=row['image'],
                   
                    selling_price=row['selling_price'],
                    landing_cost=row['landing_cost'],
                    retail_price=row['retail_price'],
                    stock=row['stock'],
                   
                    color=row['color'] if pd.notna(row['color']) else None,
                    size=row['size'] if pd.notna(row['size']) else None,
                    groupID=row['groupID'] if pd.notna(row['groupID']) else None,
                    warehouse=warehouse,
                    purchase_type=row['PURCHASE_TYPES'].strip().capitalize() if pd.notna(row['PURCHASE_TYPES']) else 'International',
                    approval_status=row['STATUS_TYPES'].strip().capitalize() if pd.notna(row['STATUS_TYPES']) else 'Disapproved',
                   
                    
                    
                
                   
                   
                    
                   
                    created_user= authUser  
                )
                if pd.notna(row['image']) and isinstance(row['image'], str) and row['image'].startswith('http'):
                    image_url = row['image']
                    response = requests.get(image_url)
                    if response.status_code == 200:
                        file_name = os.path.basename(image_url)
                        product.image.save(file_name, ContentFile(response.content), save=False)

                product.save()  # Save product

                # Set families (if ManyToManyField)
               
                product.family.set(families)

                products_data.append(product.pk)  # Add the product id to the list
            except Exception as e:
                return Response({"error": f"Error saving product: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Products successfully uploaded", "products": products_data}, status=status.HTTP_201_CREATED)


            
class OrderBulkUploadAPIView(BaseTokenView):
        parser_classes = (MultiPartParser, FormParser)

        def post(self, request, *args, **kwargs):
            
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                
                
            # Check if file is provided
            if 'file' not in request.FILES:
                return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

            # Read the file based on its type (CSV or Excel)
            excel_file = request.FILES['file']
            try:
                file_extension = os.path.splitext(excel_file.name)[1].lower()
                
                if file_extension == '.csv':
                    df = pd.read_csv(excel_file)  # Handle CSV files
                elif file_extension in ['.xlsx', '.xls']:
                    df = pd.read_excel(excel_file, engine='openpyxl')  # Handle Excel files
                else:
                    return Response({"error": "Unsupported file format. Please upload a CSV or Excel file."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"error": f"Error reading the file: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
            required_columns = [
    "Name", "Email", "Financial Status", "Paid at", "Fulfillment Status", "Fulfilled at", "Accepts Marketing", "Currency", "Subtotal", "Shipping", "Taxes",
    "Total", "Discount Code", "Discount Amount", "Shipping Method", "Created at", "Lineitem name", "Lineitem price", "Lineitem compare at price"
] + [
    f"Lineitem sku{i}" for i in range(1, 11)
] + [
    f"Lineitem quantity{i}" for i in range(1, 11)
] + [
    "Lineitem requires shipping", "Lineitem taxable", "Lineitem fulfillment status", "Billing Name", "Billing Street", "Billing Address1",
    "Billing Address2", "Billing Company", "Billing City", "Billing Zip", "Billing Province", "Billing Country", "Billing Phone", "Shipping Name", "Shipping Street",
    "Shipping Address1", "Shipping Address2", "Shipping Company", "Shipping City", "Shipping Zip", "Shipping Province", "Shipping Country", "Shipping Phone",
    "Notes", "Note Attributes", "Cancelled at", "Payment Method", "Payment Reference", "Refunded Amount", "Vendor", "Outstanding Balance", "Employee", "Location",
    "Device ID", "Id", "Tags", "Risk Level", "Source", "Lineitem discount", "Tax 1 Name", "Tax 1 Value", "Tax 2 Name", "Tax 2 Value", "Tax 3 Name", "Tax 3 Value",
    "Tax 4 Name", "Tax 4 Value", "Tax 5 Name", "Tax 5 Value", "Phone", "Receipt Number", "Duties", "Billing Province Name", "Shipping Province Name", "Payment ID",
    "Payment Terms Name", "Next Payment Due At", "Payment References"
]


      

                            
    
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return Response({"error": f"Missing columns: {', '.join(missing_columns)}"}, status=status.HTTP_400_BAD_REQUEST)

            # Process and save the data to the database
            customers_data = []
            orders_data=[]
            shipping_datas=[]
            cart_details=[]

            for _, row in df.iterrows():
                try:
                    shipping_phone = row["Billing Phone"]
                    customer = Customers.objects.filter(phone=shipping_phone).first()
                    province_=row["Shipping Province"]
                    shipping_province_=State.objects.filter(province=province_).first()


                    if not customer:
                        manager = User.objects.get(pk=2) 

                        customer =Customers(
                        email=row['Email'],
                        name=row['Billing Name'],
                        address=row['Billing Address1'],
                        phone=row["Billing Phone"],
                        city=row['Billing City'],
                        zip_code=row['Billing Zip'],
                        manager = manager # Fetch the User instance with ID 2
                        


                        
                        # created_user= authUser  
                    )
                        customer.save()
                        state_instance = shipping_province_
                        if state_instance:
                            pass
                 


                        created_user=User.objects.get(pk=2) 

                        shipping_address=Shipping(
                            name=row['Shipping Name'],
                            address=row['Shipping Address1'],
                            zipcode=row['Shipping Zip'],
                            city=row['Shipping City'],
                            state=state_instance,
                            country=row['Shipping Country'],
                            phone=row['Shipping Phone'],
                            email=row['Email'],
                            created_user=created_user,
                            customer=customer
                            
                        )
                        shipping_address.save()

                        for i in range(1, 11):  # Loop through up to 10 products
                            product_sku = row.get(f"Lineitem sku{i}")  # Extract product SKU
                            product_quantity = row.get(f"Lineitem quantity{i}") 
                            if not product_sku or not product_quantity:
                                continue 
                            try:
                                product = Products.objects.get(pk=product_sku)  # Fetch product using SKU
                                existing_cart_item = BeposoftCart.objects.filter(user=customer.manager, product=product).first()
                                if existing_cart_item:
                                    continue 
                                cart_item = BeposoftCart.objects.create(
                                     user=authUser,  # Assign the customer's manager as the cart owner
                                     product=product,
                                     quantity=int(product_quantity)
                         )
                                
                            except Products.DoesNotExist:
                                pass
                        manage_staff=User.objects.get(pk=2)
                        company = Company.objects.get(pk=1)
                        family = Family.objects.get(pk=3)
                        bank = Bank.objects.get(pk=2)
                          
                        warehouses = WareHouse.objects.get(pk=1)
                        orderdatas=Order(
                            customer=customer,
                            company=company,
                            manage_staff=manage_staff,
                            family=family,
                            billing_address =shipping_address,
                            order_date=row['Created at'],
                            state=state_instance,
                            payment_status=row['Financial Status'],
                            total_amount=row['Total'],
                            bank=bank,
                            payment_method=row['Payment Method'],
                            warehouses=warehouses,
                            status="Invoice Created",






                            
                        )
                        orderdatas.save()



                        


                        customer_data = {
                                    "customer_id": customer.id,
                                    "customer_name": customer.name,
                                    "customer_email": customer.email,
                                    "customer_phone": customer.phone,
                                    "customer_address": customer.address,
                                    "customer_city": customer.city,
                                    "customer_zip_code": customer.zip_code
                                    
            }
                        customers_data.append(customer_data)
                        # ✅ Append shipping details for new customers
                        shipping_data = {
                                 "shipping_id": shipping_address.id,
                                 "customer_id": customer.id,
                                 "shipping_name": shipping_address.name,
                                 "shipping_address": shipping_address.address,
                                 "zipcode": shipping_address.zipcode,
                                 "city": shipping_address.city,
                                 "state": shipping_address.state.name,
                                 
           
                                "country": shipping_address.country,
                                "phone": shipping_address.phone,
                                "email": shipping_address.email
            }
                        shipping_datas.append(shipping_data)
                        carts_={
                            
                            "customer_id": customer.id,
                            "customer_name": customer.name,
                            "cart_id": cart_item.id,
                            "product_id": product.id,
                            "product_name": product.name,
                            "quantity": product_quantity
                        }
                        

                        cart_details.append(carts_)
                        order_data={
                            
                            "customer_id": customer.id,
                            "customer_name": customer.name,
                            "billing_address_id": shipping_address,
                            "order_date": orderdatas.order_date,
                            "state_id": state_instance.id if state_instance else None, 
                            "payment_status": orderdatas.payment_status,
                           "total_amount": orderdatas.total_amount,
                          "payment_method": orderdatas.payment_method,
                           "warehouses_id": orderdatas.warehouses.id,
            }
                        orders_data.append(order_data)
                        
                        





                except Exception as e:
                    return Response({"error": f"Error saving product: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
                

            return Response({
    "message": "New Customers and their Shipping Addresses successfully added",
    "customers": customers_data,
    "shipping_addresses": shipping_datas,
    "carts_data":cart_details,
    "ordersss":orders_data
    
   
    
}, status=status.HTTP_201_CREATED)




class ProductStockReportView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            products = Products.objects.all()

            seen_group_ids = set()
            unique_products = []

            for product in products:
                if product.groupID not in seen_group_ids:
                    seen_group_ids.add(product.groupID)
                    unique_products.append(product)

            serializer = ProductStockviewSerializres(unique_products, many=True)

            return Response({"message": "Product list successfully retrieved","data": serializer.data}, status=status.HTTP_200_OK)

        except authUser.DoesNotExist:
            return Response({"status": "error","message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"status": "error","message": "An error occurred","errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


from django.db.models import Sum


class DashboardView(APIView):
    def get(self, request):
        try:
            # Sample data setup
            max_order = 50  # Example max order value
            today_date = timezone.now().date()
            start_of_month = today_date.replace(day=1)

            # Fetch today's orders and calculate total price
            today_orders = Order.objects.filter(updated_at__date=today_date).distinct()
            total_price = today_orders.aggregate(total_amount=Sum('total_amount'))['total_amount'] or 0

            # Calculate percentage of today's orders
            today_order_count = today_orders.count()
            today_percentage_value = (today_order_count / max_order * 100) if max_order > 0 else 0

            # Fetch approved orders
            approved_orders = Order.objects.filter(status="approved").distinct()
            approved_order_count = approved_orders.count()
            approved_percentage_value = (approved_order_count / max_order * 100) if max_order > 0 else 0

            # Fetch waiting for confirmation orders
            waiting_orders = Order.objects.filter(status="waiting_for_confirmation").distinct()
            waiting_order_count = waiting_orders.count()
            waiting_percentage_value = (waiting_order_count / max_order * 100) if max_order > 0 else 0

            # Fetch shipped orders
            shipped_orders = Order.objects.filter(status="shipped").distinct()
            shipped_order_count = shipped_orders.count()
            shipped_percentage_value = (shipped_order_count / max_order * 100) if max_order > 0 else 0

            # Fetch Proforma Invoice orders for the current month
            proforma_invoice_orders = PerfomaInvoiceOrder.objects.filter(order_date=start_of_month).distinct()
            proforma_invoice_order_count = proforma_invoice_orders.count()
            
            # Fetch Goods Return Totoal count
            goods_return = GRVModel.objects.all()
            goods_count = goods_return.count()
            
            
            # Fetch Goods Return  waitin for confirmation
            goods_waiting_condirmation = GRVModel.objects.filter(status = "pending").distinct()
            goods_count_pending = goods_waiting_condirmation.count()


            # Fetch orders waiting for approval (status = "Invoice created")
            waiting_for_approval_orders = Order.objects.filter(status="Invoice Created").distinct()
            waiting_for_approval_count = waiting_for_approval_orders.count()
            waiting_for_approval_percentage = (waiting_for_approval_count / max_order * 100) if max_order > 0 else 0

            # Final response structure
            response_data = [
                {
                    "id": 1,
                    "title": "Today Bills",
                    "order": f"{today_order_count}",
                    "percentageValue": round(today_percentage_value, 2),
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Today Bills",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 2,
                    "title": "Approved Bills",
                    "order": f"{approved_order_count}",
                    "percentageValue": round(approved_percentage_value, 2),
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Approved Bills",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 3,
                    "title": "Waiting For Confirmation",
                    "order": f"{waiting_order_count}",
                    "percentageValue": round(waiting_percentage_value, 2),
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Waiting For Confirmation",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 4,
                    "title": "Shipped",
                    "order": f"{shipped_order_count}",
                    "percentageValue": round(shipped_percentage_value, 2),
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Shipped",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 5,
                    "title": "Proforma Invoices",
                    "order": f"{proforma_invoice_order_count}",
                    "percentageValue": None,  # Optional if no percentage needed
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Proforma Invoices",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 6,
                    "title": "Goods Return",
                    "order": f"{goods_count}",
                    "percentageValue": None,  # Optional if no percentage needed
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Goods Return",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 7,
                    "title": "GRV waiting for confirmation",
                    "order": f"{goods_count_pending}",
                    "percentageValue": None,  # Optional if no percentage needed
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "GRV waiting for confirmation",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
                {
                    "id": 8,
                    "title": "Waiting For Approval",
                    "order": f"{waiting_for_approval_count}",
                    "percentageValue": round(waiting_for_approval_percentage, 2),
                    "badgeColor": "success",
                    "seriesData": [{
                        "name": "Waiting for Approval",
                        "data": [36, 21, 65, 22, 35, 50, 87, 98],
                    }],
                    "color": '["--bs-success", "--bs-transparent"]'
                },
]

            return Response(
                {"message": "Data successfully retrieved", "data": response_data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class StaffBasedCustomers(BaseTokenView):
    def get(self,request):
        try :
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
        
            customers = Customers.objects.filter(manager=authUser)
            serializer = CustomerModelSerializerView(customers, many=True)
            return Response({"data": serializer.data, "message": "Customers retrieved successfully"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def GenerateInvoice(request, pk):
    order = Order.objects.filter(pk=pk).first()
    items = OrderItem.objects.filter(order=order)
    
    total_amount = Decimal('0.0')
    total_tax_amount = Decimal('0.0')
    total_discount = Decimal('0.0')
    net_amount_before_tax = Decimal('0.0')
    total_quantity = 0

    for item in items:
        tax_rate = Decimal(item.product.tax or 0)
        quantity = item.quantity or 0
        selling_price = Decimal(item.rate or 0)
        discount = Decimal(item.discount or 0)
        rate = Decimal(item.rate or 0)

        total_price = max(selling_price - discount, Decimal('0.0'))
        exclude_price = total_price / (Decimal('1.0') + (tax_rate / Decimal('100.0')))
        tax_amount = total_price - exclude_price

        final_price = rate - discount
        total = final_price * quantity
        discount_total = discount * quantity

        item.final_price = final_price
        item.total = total
        item.tax_amount = tax_amount

        total_amount += total
        total_tax_amount += tax_amount * quantity
        total_discount += discount_total
        net_amount_before_tax += (exclude_price * quantity)
        total_quantity += quantity

    shipping_charge = Decimal(order.shipping_charge or 0)
    grand_total = total_amount + shipping_charge

    context = {
        "order": order,
        "items": items,
        "totalamount": total_amount,
        "total_tax_amount": total_tax_amount,
        "total_quantity": total_quantity,
        "discounted_amount": total_discount,
        "net_amount_before_tax": net_amount_before_tax,
        "shipping_charge": shipping_charge,
        "grand_total": grand_total,
        "exclude_price": exclude_price,
    }

    return render(request, 'invo.html', context)



# def Invo(request):
#     return render (request,"invo.html")
from collections import defaultdict

def Deliverynote(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    warehouse_items = (
        OrderItem.objects
        .filter(order=order)
        .select_related("product")
    )
    company = order.company  
    warehouse = Warehousedata.objects.filter(order=order).first()

    # Attach full product info to each item
    for item in warehouse_items:
        item.product = get_object_or_404(Products, id=item.product_id)

    # Calculate total quantity per unit
    quantity_totals = defaultdict(int)
    total_quantity_all_units = 0

    for item in warehouse_items:
        try:
            parts = str(item.quantity).split()
            number = int(parts[0])  # extract number part
            total_quantity_all_units += number
        except Exception as e:
            print("Skipping item due to error:", e)


    context = {
        "order": order,
        "warehouse_items": warehouse_items,
        "company": company,
        "warehouse": warehouse,
        "quantity_totals": dict(quantity_totals),
        "total_quantity_all_units": total_quantity_all_units,
    }

    return render(request, "deliverynote.html", context)



def generate_shipping_label(request, order_id):
    order = get_object_or_404(
        Order.objects.select_related('customer', 'billing_address'),
        id=order_id
    )

    # --- COD CALCULATION ---
    cod_amount = None

    if order.payment_status == "COD":
        total_cod = Decimal(str(order.cod_amount or 0))
        advance = Decimal(str(order.adv_cod_amount or 0))

        if order.cod_status == "PARTIAL_COD":
            remaining = total_cod
            if remaining > 0:
                cod_amount = float(remaining)
        else:
            # FULL_COD or cod_status is None
            if total_cod > 0:
                cod_amount = float(total_cod)

    order_items = OrderItem.objects.filter(order=order).select_related('product')

    shipping_data = order.billing_address
    if not shipping_data:
        raise Http404("Shipping data not found.")

    customer_data = order.customer
    if not customer_data:
        raise Http404("Customer data not found.")

    warehouse_boxes = Warehousedata.objects.filter(order=order)
    warehouse = warehouse_boxes.first()

    # BOX COUNT
    box_count = warehouse_boxes.count() or 1

    # COD PER BOX
    cod_amount_per_box = None

    if cod_amount and cod_amount > 0:
        if order.box_count and order.box_count > 0:
           
            divisor = order.box_count
        else:
            
            divisor = warehouse_boxes.count() or 1

        cod_amount_per_box = round(cod_amount / divisor, 2)

    # --- VOLUME WEIGHT ---
    volume_weight = None
    if warehouse and warehouse.length and warehouse.breadth and warehouse.height:
        volume_weight = (
            float(warehouse.length)
            * float(warehouse.breadth)
            * float(warehouse.height)
        ) / 6000

    context = {
        "order": order,
        "order_items": order_items,
        "shipping_data": shipping_data,
        "warehouse": warehouse,
        "volume_weight": round(volume_weight, 2) if volume_weight else None,
        "cod_amount": cod_amount,
        "cod_amount_per_box": cod_amount_per_box,
        "box_count": box_count, 
        "customer_data": customer_data,
    }

    return render(request, "address.html", context)


class ManagerUnderCustomer(BaseTokenView):
    def get(self, request):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Filter customers based on the manager's family relationship
            customers = Customers.objects.filter(manager__family__pk=authUser.family.pk)

            serializer = CustomerModelSerializerView(customers, many=True)

            return Response(serializer.data, status=200)

        except Customers.DoesNotExist:
            return Response({"error": "No customers found for the given manager."}, status=404)

        except Exception as e:
            return Response({"error": "An unexpected error occurred.", "details": str(e)}, status=500)
        
        
        
        
class FamilyBasedOrderGetView(BaseTokenView):
    def get(self, request):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Filter customers based on the manager's family relationship
            customers = Order.objects.filter(family=authUser.family.pk).order_by('-id')

            serializer = FamilyOrderModelSerilizer(customers, many=True)

            return Response(serializer.data, status=200)

        except Customers.DoesNotExist:
            return Response({"error": "No customers found for the given manager."}, status=404)

        except Exception as e:
            return Response({"error": "An unexpected error occurred.", "details": str(e)}, status=500)
        


class FamilyBasedBDOBDMOrderGetView(BaseTokenView):
    def get(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            orders = Order.objects.filter(
                family=authUser.family.pk,
                manage_staff__department_id__name__in=["BDO", "BDM", "SD"]
            ).order_by("-id")

            serializer = FamilyOrderModelSerilizer(orders, many=True)
            return Response(serializer.data, status=200)

        except Exception as e:
            return Response(
                {
                    "error": "An unexpected error occurred.",
                    "details": str(e)
                },
                status=500
            )


class BDOBDMFamilyBasedOrderGetView(BaseTokenView):
    def get(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "")
            status_filter = request.GET.get("status", "")
            staff_filter = request.GET.get("staff", "")
            start_date = request.GET.get("start_date", "")
            end_date = request.GET.get("end_date", "")

            # Base queryset
            orders = Order.objects.select_related(
                "manage_staff", "customer", "state", "family", "company", "billing_address"
            ).prefetch_related("warehouse").filter(
                family=authUser.family.pk,
                manage_staff__department_id__name__in=["BDO", "BDM", "SD"]
            ).order_by("-id")

            # Search filter
            if search:
                if search.isdigit():
                    orders = orders.filter(invoice__iregex=rf"{search}$")
                else:
                    orders = orders.filter(
                        Q(invoice__icontains=search) |
                        Q(customer__name__icontains=search)
                    )

            # Status filter
            if status_filter:
                orders = orders.filter(status__iexact=status_filter)

            # Staff filter
            if staff_filter:
                orders = orders.filter(manage_staff__name__icontains=staff_filter)

            # Date filters
            if start_date:
                orders = orders.filter(order_date__gte=start_date)

            if end_date:
                orders = orders.filter(order_date__lte=end_date)

            # Counts before pagination
            invoice_counts = orders.aggregate(
                invoice_created_count=Count("id", filter=Q(status="Invoice Created")),
                invoice_approved_count=Count("id", filter=Q(status="Waiting For Confirmation"))
            )

            # Pagination
            paginator = StandardPagination()
            paginated_orders = paginator.paginate_queryset(orders, request)

            serializer = FamilyOrderModelSerilizer(paginated_orders, many=True)
            results = serializer.data

            # Extra fields
            for idx, order in enumerate(paginated_orders):
                family = getattr(order, "family", None)

                results[idx]["family_id"] = family.id if family else None
                results[idx]["family_name"] = family.name if family else None

                results[idx]["locked_by"] = order.locked_by.username if order.locked_by else None
                results[idx]["locked_at"] = order.locked_at.isoformat() if order.locked_at else None

            return paginator.get_paginated_response({
                "invoice_created_count": invoice_counts["invoice_created_count"],
                "invoice_approved_count": invoice_counts["invoice_approved_count"],
                "results": results
            })

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Orders not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class WarehouseAddView(BaseTokenView):
    def post(self, request):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehouse_data=WarehouseDetailSerializer(data=request.data)
            if warehouse_data.is_valid():
                warehouse_data.save()
                return Response({"message": "Warehouse added successfully"}, status=status.HTTP_201_CREATED)
            return Response(warehouse_data.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def get(self, request):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehouse = WareHouse.objects.all()
            serializer = WarehouseDetailSerializer(warehouse, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WarehouseGetView(BaseTokenView):
    def put(self,request,pk):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehouse = WareHouse.objects.get(pk=pk)
            serializer = WarehouseDetailSerializer(warehouse, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Warehouse updated successfully"}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
       

    def get(self,request,pk):
        try:
            # Retrieve the authenticated user and handle token errors
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehouse = WareHouse.objects.get(pk=pk)
            serializer = WarehouseDetailSerializer(warehouse)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)  
   
        
class InternalTransferView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            data = request.data.copy()
            data["created_by"] = authUser.pk

            serializer = InternalTransferSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"message": "Internal transfer created successfully", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfers = InternalTransfer.objects.all().order_by('-id')
            serializer = InternalTransferViewSerializer(transfers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class InternalTransferByIdView(BaseTokenView):
    def get(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfer = InternalTransfer.objects.get(id=id)
            serializer = InternalTransferViewSerializer(transfer)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except InternalTransfer.DoesNotExist:
            return Response({"error": "Transfer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfer = InternalTransfer.objects.get(id=id)
            serializer = InternalTransferSerializer(transfer, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Transfer updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except InternalTransfer.DoesNotExist:
            return Response({"error": "Transfer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CODTransferView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            data = request.data.copy()
            data["created_by"] = authUser.pk

            serializer = CODTransferSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"message": "COD transfer created successfully", "data": serializer.data},
                    status=status.HTTP_201_CREATED
                )
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfers = CODTransfer.objects.all().order_by('-id')
            serializer = CODTransferViewSerializer(transfers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class CODTransferByIdView(BaseTokenView):
    def get(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfer = CODTransfer.objects.get(id=id)
            serializer = CODTransferViewSerializer(transfer)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except CODTransfer.DoesNotExist:
            return Response({"error": "COD Transfer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            transfer = CODTransfer.objects.get(id=id)
            serializer = CODTransferSerializer(transfer, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "COD Transfer updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except CODTransfer.DoesNotExist:
            return Response({"error": "COD Transfer not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

class ProductByWarehouseView(BaseTokenView):
    def get(self, request, warehouse_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Check if the warehouse exists
            warehouse = WareHouse.objects.filter(pk=warehouse_id).first()
            if not warehouse:
                return Response(
                    {"message": "Warehouse not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Filter products by warehouse_id and approval_status being either 'Approved' or 'Disapproved'
            products = Products.objects.filter(
                warehouse=warehouse, 
                approval_status__in=['Approved', 'Disapproved']
            )
            if not products.exists():
                return Response(
                    {"message": "No products found in this warehouse with the required approval status"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Initialize a set to track unique groupIDs
            seen_group_ids = set()
            unique_products = []

            # Iterate through products and filter out duplicates by groupID
            for product in products:
                if product.groupID not in seen_group_ids:
                    seen_group_ids.add(product.groupID)
                    unique_products.append(product)

            # Serialize the unique products list
            serializer = ProductSingleviewSerializres(unique_products, many=True)

            return Response({
                "message": "Product list successfully retrieved",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except authUser.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User does not exist"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LockedStockInvoicesView(APIView):
    def get(self, request, product_id):
        try:
            # Only consider active orders that might lock stock
            active_statuses = [
                "Pending", "Waiting For Confirmation", 
                "Packing under progress", "To Print",
                "Packed", "Ready to ship", 
                "Invoice Created", "Invoice Approved"
            ]

            order_items = OrderItem.objects.filter(
                product_id=product_id,
                order__status__in=active_statuses
            ).select_related('order')

            data = [{
                'invoice': item.order.invoice,
                'quantity_locked': item.quantity,
                'status': item.order.status,
                'order_date': item.order.order_date,
            } for item in order_items]

            return Response({'locked_invoices': data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

class WareHouseOrdersView(BaseTokenView):
    def get(self, request, warehouse_id):
        try:
            # Authenticate user from the token (same approach as in OrderListView)
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Ensure the warehouse exists
            warehouse = get_object_or_404(WareHouse, pk=warehouse_id)
            if authUser.warehouse_id != warehouse:
                return Response(
                    {"status": "error", "message": "You are not authorized to view orders for this warehouse."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Fetch all orders for the given warehouse
            orders = Order.objects.filter(warehouses=warehouse)
            if not orders.exists():
                return Response(
                    {"status": "error", "message": "No orders found for the given warehouse."},
                    status=status.HTTP_404_NOT_FOUND
                )



            # Serialize the order data
            serializer = OrderModelSerilizer(orders, many=True)

            # Return the serialized data in the response
            return Response(serializer.data, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Orders not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AttendanceView(BaseTokenView):
    def get(self, request):
        try:
            attendance_data=Attendance.objects.all().order_by('-date')
            serializer = AttendanceSerializer(attendance_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Attendance not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AttendanceUpdateAPIView(APIView):
    def put(self, request, pk):
        try:
            attendance = Attendance.objects.get(pk=pk)
            serializer = AttendanceSerializer(attendance, data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AllStaffAttendanceReportAPIView(APIView):
    def get(self, request):
        """
        Get the attendance report of all staff showing the count of Present, Half Day Leave, and Absent days up to today, excluding Sundays.
        """
        try:
            today = date.today()
            report_data = []

            # Loop through each staff member
            for staff in User.objects.all():
                # Filter attendance records up to today, excluding Sundays
                attendance_records = Attendance.objects.filter(
                    staff=staff,
                    date__lte=today
                ).exclude(date__week_day=1)  # Exclude Sundays (1 = Sunday in Django `date__week_day`)

                report_data.append({
                    "staff_id": staff.id,
                    "staff_name": staff.name,
                    "present_count": attendance_records.filter(attendance_status="Present").count(),
                    "half_day_leave_count": attendance_records.filter(attendance_status="Half Day Leave").count(),
                    "absent_count": attendance_records.filter(attendance_status="Absent").count(),
                })

            # Serialize and return the data
            serializer = AttendanceSummarySerializer(report_data, many=True)
            return Response(
                {"message": "Attendance report retrieved successfully, excluding Sundays.", "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"message": "An unexpected error occurred.", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )  
        
class StaffAttendanceAbsenceAPIView(APIView):
    def get(self, request, staff_id):
        """
        Get the attendance report of a single staff member, showing absence and half-day leave up to today.
        """
        try:
            # Get the staff member
            staff = User.objects.filter(id=staff_id).first()
            if not staff:
                return Response(
                    {"message": "Staff member not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Generate the response data using the serializer
            serializer = AttendanceAbsenceSerializer(staff)
            return Response(
                {"message": "Attendance report retrieved successfully.", "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"message": "An unexpected error occurred.", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )              


class UpdateCartPricesView(BaseTokenView):
    def put(self, request):
        try:
            # Step 1: Get the authenticated user from the token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            # Step 2: Check if the user has the required designation
            if authUser.designation not in ['Accounts', 'Admin']:
                return Response(
                    {"status": "error", "message": "User does not have permission to update prices"},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Step 3: Get the cart items of the authenticated user
            cart_items = BeposoftCart.objects.filter(user=authUser)

            if not cart_items.exists():
                return Response(
                    {"status": "error", "message": "No cart items found"},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Step 4: Deserialize the data and update the prices
            serializer = UpdateCartPricesSerializer(cart_items, many=True, data=request.data, partial=True)
            
            if serializer.is_valid():
                serializer.save()  # Save updated prices to the products
                
                # Step 5: Reflect the updated prices in the order (if needed)
                for item in cart_items:
                    item.order_creation_time = item.updated_at  # Update the order creation time
                    item.save()

                return Response(
                    {"status": "success", "message": "Prices updated successfully"},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"status": "error", "message": "Invalid data", "errors": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class FinancereportAPIView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            bank_data = Bank.objects.all()
            bank_serializer = FinanaceReceiptSerializer(bank_data, many=True)

            return Response({
                "bank_data": bank_serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class BankAccountTypeReportView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            banks = Bank.objects.filter(account_type__account_type="OD ACCOUNT")

            final_data = []

            for bank in banks:

                # CREDIT (PAYMENTS)
                payments_qs = bank.payments.all().annotate(
                    date=TruncDate('received_at')
                ).values('date', 'amount', 'payment_receipt')

                advance_qs = bank.advance_receipts.all().annotate(
                    date=TruncDate('received_at')
                ).values('date', 'amount', 'payment_receipt')

                bank_receipt_qs = bank.bank_receipts.all().annotate(
                    date=TruncDate('received_at')
                ).values('date', 'amount', 'payment_receipt')

                internal_received_qs = InternalTransfer.objects.filter(
                    receiver_bank=bank
                ).annotate(
                    date=TruncDate('created_at')
                ).values('date', 'amount', 'transactionID')

                cod_received_qs = CODTransfer.objects.filter(
                    receiver_bank=bank
                ).annotate(
                    date=TruncDate('created_end')
                ).values('date', 'amount', 'payment_receipt')

                credit_entries = []

                for p in payments_qs:
                    credit_entries.append({
                        "date": p["date"],
                        "type": "CREDIT",
                        "amount": float(p["amount"] or 0),
                        "reference": p["payment_receipt"]
                    })

                for a in advance_qs:
                    credit_entries.append({
                        "date": a["date"],
                        "type": "CREDIT",
                        "amount": float(a["amount"] or 0),
                        "reference": a["payment_receipt"]
                    })

                for b in bank_receipt_qs:
                    credit_entries.append({
                        "date": b["date"],
                        "type": "CREDIT",
                        "amount": float(b["amount"] or 0),
                        "reference": b["payment_receipt"]
                    })

                for i in internal_received_qs:
                    credit_entries.append({
                        "date": i["date"],
                        "type": "CREDIT",
                        "amount": float(i["amount"] or 0),
                        "reference": f"INTERNAL RECEIVED - {i['transactionID']}"
                    })

                for c in cod_received_qs:
                    credit_entries.append({
                        "date": c["date"],
                        "type": "CREDIT",
                        "amount": float(c["amount"] or 0),
                        "reference": f"COD RECEIVED - {c['payment_receipt']}"
                    })

                # DEBIT (BANK EXPENSES)
                expenses_qs = ExpenseModel.objects.filter(
                    bank=bank
                ).annotate(
                    date=TruncDate('expense_date')
                ).values('date', 'amount', 'purpose_of_payment')

                internal_sent_qs = InternalTransfer.objects.filter(
                    sender_bank=bank
                ).annotate(
                    date=TruncDate('created_at')
                ).values('date', 'amount', 'transactionID')

                cod_sent_qs = CODTransfer.objects.filter(
                    sender_bank=bank
                ).annotate(
                    date=TruncDate('created_at')
                ).values('date', 'amount', 'payment_receipt')

                debit_entries = []

                for e in expenses_qs:
                    debit_entries.append({
                        "date": e["date"],
                        "type": "DEBIT",
                        "amount": float(e["amount"] or 0),
                        "reference": e["purpose_of_payment"]
                    })

                for t in internal_sent_qs:
                    debit_entries.append({
                        "date": t["date"],
                        "type": "DEBIT",
                        "amount": float(t["amount"] or 0),
                        "reference": f"INTERNAL TRANSFER - {t['transactionID']}"
                    })

                for c in cod_sent_qs:
                    debit_entries.append({
                        "date": c["date"],
                        "type": "DEBIT",
                        "amount": float(c["amount"] or 0),
                        "reference": f"COD TRANSFER - {c['payment_receipt']}"
                    })

                # GROUP DATA BY DATE
                grouped = defaultdict(lambda: {"debit": [], "credit": []})

                for d in debit_entries:
                    grouped[str(d["date"])]["debit"].append({
                        "amount": float(d["amount"]),
                        "reference": d["reference"]
                    })

                for c in credit_entries:
                    grouped[str(c["date"])]["credit"].append({
                        "amount": float(c["amount"]),
                        "reference": c["reference"]
                    })

                daily_data = []
                for date, values in grouped.items():
                    daily_data.append({
                        "date": date,
                        "debit": values["debit"],
                        "credit": values["credit"],
                        "total_debit": sum(float(x["amount"]) for x in values["debit"]),
                        "total_credit": sum(float(x["amount"]) for x in values["credit"]),
                    })

                # SORT BY DATE
                daily_data = sorted(daily_data, key=lambda x: x["date"])

                # OPENING + CLOSING + INTEREST CALCULATION
                running_balance = float(bank.open_balance or 0)
                first_opening_balance = running_balance

                # Interest Rate
                rate = float(bank.interest_rate or 0)

                # Running total interest
                total_interest = 0

                for entry in daily_data:
                    entry["opening"] = round(running_balance, 2)

                    entry["closing"] = round(
                        running_balance + float(entry["total_credit"]) - float(entry["total_debit"]),
                        2
                    )

                    closing_balance = float(entry["closing"])

                    used_amount = first_opening_balance - closing_balance

                    if used_amount < 0:
                        used_amount = 0

                    daily_interests = ((closing_balance * rate) / 100 ) / 365
                    daily_interest = (daily_interests * -1)
                    total_interest += daily_interest

                    entry["daily_interest"] = round(daily_interest, 4)
                    entry["total_interest"] = round(total_interest, 4)


                    running_balance = closing_balance

                final_data.append({
                    "bank_id": bank.id,
                    "bank_name": bank.name,
                    "interest_rate": float(bank.interest_rate or 0),
                    "open_balance": float(bank.open_balance or 0),
                    "daily_data": daily_data
                })

            return Response({
                "status": "success",
                "bank_data": final_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        
class CustomerUploadView(BaseTokenView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            if 'file' not in request.FILES:
                return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)

            # Read the file based on its type (CSV or Excel)
            excel_file = request.FILES['file']
            try:
                file_extension = os.path.splitext(excel_file.name)[1].lower()
                if file_extension == '.csv':
                    df = pd.read_csv(excel_file)  
                elif file_extension in ['.xlsx', '.xls']:
                    df = pd.read_excel(excel_file, engine='openpyxl')  # Handle Excel files
                else:
                    return Response({"error": "Unsupported file format. Please upload a CSV or Excel file."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"error": f"Error reading the file: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
            
            required_columns = ["id", "companies_id", "ordre", "label", "adress", "zipcode", "city", "state", "country", "number", "mobile", "mail",
                                "created_at", "updated_at", "deleted_at"]
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return Response({"error": f"Missing columns: {', '.join(missing_columns)}"}, status=status.HTTP_400_BAD_REQUEST)

            customers_data = []
            errors = []

            # ✅ Fetch existing phone numbers from the database
            existing_phones = set(Customers.objects.values_list('phone', flat=True))
            new_customers = {}  # Store unique customers to insert

            for index, row in df.iterrows():
                try:
                    state_instance = None
                    if pd.notna(row['state']):
                        state_instance = State.objects.filter(name=row['state']).first()

                    # ✅ Validate phone number
                    phone_number = str(row['number']).strip() if pd.notna(row['number']) else None
                    if not phone_number:
                        errors.append({"row": index, "error": "Missing phone number"})
                        continue  # Skip row

                    # ✅ Check if the customer already exists in the database
                    if phone_number in existing_phones:
                        continue  # ✅ Skip if already exists in the database
                    
                    # ✅ Check if customer is already added in this batch (to prevent duplicate creation)
                    if phone_number in new_customers:
                        continue  # ✅ Skip if already added in this batch
                    
                    # ✅ If customer does not exist, add to batch
                    customer = Customers(
                        name=row['label'],
                        phone=phone_number,
                        alt_phone=row['mobile'] if pd.notna(row['mobile']) else None,
                        email=row['mail'] if pd.notna(row['mail']) else None,
                        address=row['adress'] if pd.notna(row['adress']) else None,
                        zip_code=row['zipcode'] if pd.notna(row['zipcode']) else None,
                        city=row['city'] if pd.notna(row['city']) else None,
                        state=state_instance,
                        created_at=row['created_at'] if pd.notna(row['create'
                        'd_at']) else timezone.now(),
                        manager=authUser
                    )
                    customer.save()

                    # ✅ Add new customer to dictionary and database lookup
                    existing_phones.add(phone_number)  # Prevents adding again in the future
                    new_customers[phone_number] = customer

                    customer_data = {
                        "customer_id": customer.id,
                        "customer_name": customer.name,
                        "customer_phone": customer.phone,
                        "customer_alt_phone": customer.alt_phone,
                        "customer_email": customer.email,
                        "customer_address": customer.address,
                        "customer_zip_code": customer.zip_code,
                        "customer_city": customer.city,
                        "customer_state": customer.state.name if customer.state else None,
                        "customer_created_at": customer.created_at
                    }
                    customers_data.append(customer_data)

                except Exception as e:
                    errors.append({"row": index, "error": str(e)})
                    continue 

            # ✅ Return Response
            return Response({
                "message": "Customers successfully uploaded",
                "customers": customers_data,
                "errors": errors
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AllpaymentReceiptsView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            payments = PaymentReceipt.objects.all().order_by('-received_at')  # latest first
            serializer = PaymentReceiptSerializerView(payments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReceiptViewbyId(BaseTokenView):
    def get(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            pays=PaymentReceipt.objects.get(id=id)
            serializer_data = PaymentReceiptSerializerView(pays)
            return Response(serializer_data.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    def put(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            pay=PaymentReceipt.objects.get(id=id)
            serializer = PaymentRecieptSerializers(pay,data=request.data,partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "error", "message": "An error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


logger = logging.getLogger(__name__)

def send_shipping_id(name, phone_number, order_id, tracking_id):
    sms_alert_username = 'francisgoskates@gmail.com'  # Replace with actual SMSAlert username
    sms_alert_password = 'Need2open@123'  # Replace with actual SMSAlert password
    sms_alert_sender_id = 'BEPOST'  # Ensure this matches your approved Sender ID
    template_id = '1707164275994735387'  # ✅ Updated with your correct Template ID

    # ✅ Message must exactly match the approved template format
    message = (f"Hello {name}, Your Order #{order_id} Was shipped from Bepositive via Indian Post "
               f"Your Tracking Number is: {tracking_id} Track Order Status: Shipped "
               f"for any query call 9526792642")

    url = 'https://www.smsalert.co.in/api/push.json'

    payload = {
        'user': sms_alert_username,
        'pwd': sms_alert_password,
        'sender': sms_alert_sender_id,
        'mobileno': phone_number,
        'text': message,  # ✅ Must match the template format
        'template_id': template_id,  # ✅ Must be correct
    }

    logger.info(f"Sending SMS with payload: {payload}")  # Debugging

    try:
        response = requests.post(url, data=payload)
        logger.info(f"SMSAlert API Response: {response.status_code} - {response.text}")  # Log full response

        if response.status_code != 200:
            logger.error(f"SMSAlert API Error: {response.text}")  # Log actual error message
            return False

        response_data = response.json()
        return response_data.get('status') == 'success'

    except requests.exceptions.RequestException as e:
        logger.error(f"RequestException: {e}", exc_info=True)
        return False
    
    
class SendShippingIDView(APIView):
    def post(self, request):
        name = request.data.get('name')
        phone_number = request.data.get('phone')
        order_id = request.data.get('order_id')
        tracking_id = request.data.get('tracking_id')

        if not all([name, phone_number, order_id, tracking_id]):
            return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

        phone_number = phone_number.strip()

        # Validate phone number format
        if not phone_number.isdigit() or len(phone_number) != 10:
            return Response({'error': 'Invalid phone number format'}, status=status.HTTP_400_BAD_REQUEST)
    
        # Send Shipping ID via SMS
        if send_shipping_id(name, phone_number, order_id, tracking_id):
            return Response({'message': 'Shipping ID sent successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send Shipping ID'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from django.utils import timezone
from django.shortcuts import render, get_object_or_404

def GeneratePerformaInvoice(request, invoice_number):
    order = get_object_or_404(PerfomaInvoiceOrder, invoice=invoice_number)

    # Use the related_name to fetch items
    items = order.perfoma_items.select_related("product").all()

    # Ensure these are always defined
    original_order = None
    bank = None
    exclude_price = 0.0  # in case there are no items

    try:
        original_order = Order.objects.get(invoice=invoice_number)
        bank = original_order.bank
    except Order.DoesNotExist:
        pass

    total_amount = 0.0
    total_tax_amount = 0.0
    total_discount = 0.0
    net_amount_before_tax = 0.0
    total_quantity = 0

    for item in items:
        tax_rate = item.product.tax or 0.0
        quantity = item.quantity or 0
        selling_price = item.product.selling_price or 0.0
        discount = item.discount or 0.0
        rate = item.rate or 0.0

        total_price = max(rate - discount, 0.0)
        exclude_price = total_price / (1 + (tax_rate / 100.0)) if tax_rate else total_price
        tax_amount = total_price - exclude_price

        final_price = rate - discount
        total = rate * quantity
        discount_total = discount * quantity

        # annotate (not saved to DB)
        item.final_price = final_price
        item.total = total
        item.tax_amount = tax_amount

        total_amount += total
        total_tax_amount += tax_amount * quantity
        total_discount += discount_total
        net_amount_before_tax += (rate * quantity)
        total_quantity += quantity

    shipping_charge = order.shipping_charge or 0.0
    grand_total = total_amount + shipping_charge

    # Pick a safe invoice date for the template
    invoice_date = (
        original_order.updated_at if original_order
        else timezone.now()
    )

    context = {
        "order": order,
        "items": items,
        "bank": bank,
        "totalamount": total_amount,
        "total_tax_amount": total_tax_amount,
        "total_quantity": total_quantity,
        "discounted_amount": total_discount,
        "net_amount_before_tax": net_amount_before_tax,
        "shipping_charge": shipping_charge,
        "grand_total": grand_total,
        "exclude_price": exclude_price,
        "original_order": original_order,  # may be None; template won’t depend on it now
        "invoice_date": invoice_date,
    }
    return render(request, "performainvoice.html", context)


class CountryCodeView(APIView):
    def get(self, request):
        codes = CountryCode.objects.all().order_by('id')
        serializer = CountryCodeSerializer(codes, many=True)
        return Response({'status': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = CountryCodeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'data': serializer.data}, status=status.HTTP_201_CREATED)
        return Response({'status': 'error', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class CountryCodeDetailView(APIView):
    def get(self, request, pk):
        code = get_object_or_404(CountryCode, pk=pk)
        serializer = CountryCodeSerializer(code)
        return Response({'status': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, pk):
        code = get_object_or_404(CountryCode, pk=pk)
        serializer = CountryCodeSerializer(code, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'data': serializer.data}, status=status.HTTP_200_OK)
        return Response({'status': 'error', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    

class RackDetailsView(BaseTokenView):   
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = RackDetailsModelSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "message": "Rack created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            # Authenticate the user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            racks = RackDetailsModel.objects.all().order_by('-id')
            serializer = RackDetailsModelSerializer(racks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class RackDetailByIdView(BaseTokenView):
    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                rack = RackDetailsModel.objects.get(pk=pk)
            except RackDetailsModel.DoesNotExist:
                return Response({"error": "Rack not found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = RackDetailsModelSerializer(rack)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                rack = RackDetailsModel.objects.get(pk=pk)
            except RackDetailsModel.DoesNotExist:
                return Response({"error": "Rack not found."}, status=status.HTTP_404_NOT_FOUND)

            # Optional: Prevent reducing column count
            new_column_count = request.data.get('number_of_columns')
            if new_column_count and int(new_column_count) < len(rack.column_names):
                return Response(
                    {"error": "Reducing number_of_columns is not allowed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = RackDetailsModelSerializer(rack, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # This will trigger your model logic to append new column_names
                return Response({
                    "message": "Rack updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class ProductCategoryView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = ProductCategorySerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "message": "Product category created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            categories = ProductCategoryModel.objects.all().order_by('-id')
            serializer = ProductCategorySerializer(categories, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DataLogCreateView(BaseTokenView):
    def post(self, request):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        serializer = DataLogCreateSerializer(data=request.data)
        if serializer.is_valid():
            log = DataLog.objects.create(
                user=auth_user,
                **serializer.validated_data,  # accepts: order, before_data, after_data
            )
            return Response(DataLogViewSerializer(log).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DataLogListView(BaseTokenView):
    def get(self, request):
        auth_user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        qs = DataLog.objects.all().order_by('-created_at')

        order_id = request.GET.get('order')      # ?order=2332
        user_id = request.GET.get('user')        # ?user=17
        dt_from = request.GET.get('from')        # YYYY-MM-DD
        dt_to = request.GET.get('to')            # YYYY-MM-DD

        if order_id:
            qs = qs.filter(order_id=order_id)
        if user_id:
            qs = qs.filter(user_id=user_id)
        if dt_from:
            qs = qs.filter(created_at__date__gte=dt_from)
        if dt_to:
            qs = qs.filter(created_at__date__lte=dt_to)

        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 100))
        start = (page - 1) * page_size
        end = start + page_size

        total_count = qs.count()  # before slicing
        qs = qs[start:end]

        serializer = DataLogViewSerializer(qs, many=True)

        return Response({
            "page": page,
            "page_size": page_size,
            "count": total_count,
            "results": serializer.data,
        }, status=status.HTTP_200_OK)

class DeleteOldDataLogsView(BaseTokenView):
    """
    DELETE the 50 oldest DataLog records.
    """
    def delete(self, request):
        try:
            with transaction.atomic():
                # Get the IDs of the 50 oldest logs
                oldest_ids = list(
                    DataLog.objects.order_by('created_at')
                    .values_list('id', flat=True)[:100]
                )

                if not oldest_ids:
                    return Response(
                        {"message": "No DataLog entries to delete."},
                        status=status.HTTP_200_OK
                    )

                # Delete by IDs
                deleted_count, _ = DataLog.objects.filter(id__in=oldest_ids).delete()

                return Response(
                    {"message": f"Deleted {deleted_count} oldest DataLog entries successfully."},
                    status=status.HTTP_200_OK
                )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CreateWarehouseOrder(BaseTokenView):
    @transaction.atomic
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cart_qs = BeposoftCart.objects.select_related("product").filter(user=authUser)
            if not cart_qs.exists():
                return Response(
                    {"status": "error", "message": "Cart is empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = WarehouseOrderSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(
                    {
                        "status": "error",
                        "message": "Validation failed",
                        "errors": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            warehouse_order = serializer.save(manage_staff=authUser)

            items_to_create = []
            lock_map = {}  # product_id -> qty to lock

            for cart in cart_qs:
                product = cart.product
                qty = int(cart.quantity or 0)
                if qty <= 0:
                    continue

                # check availability
                available = max(0, int(product.stock or 0) - int(product.locked_stock or 0))
                if qty > available:
                    return Response(
                        {
                            "status": "error",
                            "message": f"Not enough available stock for '{product.name}'. "
                                       f"Need {qty}, available {available}"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                items_to_create.append(
                    WarehouseOrderItem(
                        order=warehouse_order,
                        product=product,
                        variant=None,
                        size=None,
                        description="",
                        quantity=qty,
                        rack_details=[],
                    )
                )

                lock_map[product.id] = lock_map.get(product.id, 0) + qty

            if not items_to_create:
                return Response(
                    {"status": "error", "message": "No valid items in cart."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            WarehouseOrderItem.objects.bulk_create(items_to_create)

            prods = Products.objects.select_for_update().filter(id__in=lock_map.keys())
            for p in prods:
                p.locked_stock = (p.locked_stock or 0) + lock_map[p.id]
                p.save(update_fields=["locked_stock"])

            cart_qs.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Warehouse order created successfully",
                    "data": WarehouseOrderSerializer(warehouse_order).data
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": f"Something went wrong: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
class WarehouseOrderView(BaseTokenView):

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            orders = WarehouseOrder.objects.prefetch_related("items").order_by("-id")

            return Response(
                {
                    "status": "success",
                    "data": WarehouseOrderGetSerializer(orders, many=True).data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": f"Something went wrong: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WarehouseOrderByWarehouseView(BaseTokenView):

    def get(self, request, warehouse_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # filter orders for the given warehouse_id
            orders = WarehouseOrder.objects.filter(
                warehouses_id=warehouse_id
            ).prefetch_related("items").order_by("-id")

            if not orders.exists():
                return Response(
                    {
                        "status": "error",
                        "message": f"No orders found for warehouse id {warehouse_id}"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            return Response(
                {
                    "status": "success",
                    "data": WarehouseOrderSerializer(orders, many=True).data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": f"Something went wrong: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class WarehouseOrderIDView(BaseTokenView):

    def get(self, request, invoice=None):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order = WarehouseOrder.objects.prefetch_related("items").filter(invoice=invoice).first()
            if not order:
                return Response(
                    {"status": "error", "message": "Order not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            return Response(
                {
                    "status": "success",
                    "data": WarehouseOrderSerializer(order).data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Something went wrong: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class WarehouseOrderUpdateView(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order = get_object_or_404(WarehouseOrder, pk=pk)
            old_status = order.status

            serializer = WarehouseOrderSerializer(order, data=request.data, partial=True)
            if serializer.is_valid():
                with transaction.atomic():
                    updated_order = serializer.save()

                    #  If status changes to Rejected / Completed / Cancelled,
                    #    subtract rack_details qty from product.rack_details & locked_stock
                    new_status = updated_order.status
                    if (
                        old_status not in ["Rejected", "Completed", "Cancelled"]
                        and new_status in ["Rejected", "Completed", "Cancelled"]
                    ):
                        for item in updated_order.items.select_related("product").all():
                            product = item.product
                            product_racks = product.rack_details or []
                            item_racks = item.rack_details or []

                            # map by (rack_id, column_name)
                            rack_map = {
                                (r.get("rack_id"), r.get("column_name")): r
                                for r in product_racks
                            }
                            for r in item_racks:
                                key = (r.get("rack_id"), r.get("column_name"))
                                if key in rack_map:
                                    pr = rack_map[key]
                                    pr["rack_lock"] = max(
                                        (pr.get("rack_lock") or 0) - (r.get("quantity") or 0),
                                        0,
                                    )

                            # update locked_stock and rack_details
                            product.rack_details = product_racks
                            product.locked_stock = max(
                                (product.locked_stock or 0) - item.quantity, 0
                            )
                            product.save(update_fields=["rack_details", "locked_stock"])

                return Response(
                    {"status": "success", "data": serializer.data},
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Update failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class WarehouseOrderItemUpdateView(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            item = get_object_or_404(WarehouseOrderItem, pk=pk)

            serializer = WarehouseOrderItemSerializer(item, data=request.data, partial=True)
            if serializer.is_valid():
                with transaction.atomic():
                    # 1️⃣ Save the updated order item
                    updated_item = serializer.save()

                    # 2️⃣ Add the quantities to the product's rack_lock
                    self._update_product_rack_lock(updated_item)

                return Response(
                    {"status": "success", "data": serializer.data},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Update failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _update_product_rack_lock(self, order_item):
        """
        Merge the rack_details quantity of WarehouseOrderItem
        into the rack_lock of Products.rack_details.
        """
        product = order_item.product
        product_racks = product.rack_details or []
        item_racks = order_item.rack_details or []

        # Convert to dict keyed by (rack_id, column_name) for easy update
        product_rack_map = {
            (r.get("rack_id"), r.get("column_name")): r for r in product_racks
        }

        for r in item_racks:
            key = (r.get("rack_id"), r.get("column_name"))
            if key in product_rack_map:
                pr = product_rack_map[key]
                pr["rack_lock"] = (pr.get("rack_lock") or 0) + (r.get("quantity") or 0)
            else:
                # if the rack is new in product, optionally append it
                product_racks.append({
                    **r,
                    "rack_lock": r.get("quantity", 0)
                })

        product.rack_details = product_racks
        product.save(update_fields=["rack_details"])


class ProductDateWiseReportView(APIView): 

    def get(self, request):
        try:
            # Optional filters from query parameters
            start_date = request.query_params.get('start_date')
            end_date   = request.query_params.get('end_date')

            filters = {'order__status': 'Shipped'}
            
            if start_date and end_date:
                filters['order__order_date__range'] = [start_date, end_date]

            # Fetch OrderItem rows
            queryset = (
                OrderItem.objects
                .select_related('order', 'product')
                .filter(**filters)
                .annotate(
                    calculated_total=ExpressionWrapper(
                        F('quantity') * (F('rate') - F('discount')),
                        output_field=DecimalField(max_digits=12, decimal_places=2)
                    )
                )
                .order_by('-order__order_date')
            )

            serializer = ProductDateWiseReportSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            # Catch unexpected errors
            return Response(
                {"error": f"Unable to fetch product report: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


def warehouse_delivery_note(request, order_id):
    order = get_object_or_404(WarehouseOrder, id=order_id)
    items = WarehouseOrderItem.objects.filter(order=order).select_related('product')

    total_quantity = sum(item.quantity for item in items)

    context = {
        "order": order,
        "items": items,
        "total_quantity": total_quantity,
    }

    return render(request, "warehousedeliverynote.html", context)


class ContactInfoCreateView(BaseTokenView):
    """GET all customers / POST new customer"""

    def get(self, request):
        try:
            contactinfo = ContactInfo.objects.select_related("state", "created_by").all()
            serializer = ContactInfoSerializer(contactinfo, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = ContactInfoSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(created_by=authUser) 
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ContactInfoUpdateView(BaseTokenView):
    """GET a single customer / PUT update by id"""

    def get(self, request, pk):
        try:
            contactinfo = get_object_or_404(ContactInfo.objects.select_related("state", "created_by"), pk=pk)
            serializer = ContactInfoSerializer(contactinfo)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            contactinfo = get_object_or_404(ContactInfo, pk=pk)
            serializer = ContactInfoSerializer(contactinfo, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class ContactInfoByStaffView(BaseTokenView):
    """GET all ContactInfo by created_by / PUT update all ContactInfo by created_by"""

    def get(self, request, created_by):
        try:
            contactinfos = ContactInfo.objects.select_related(
                "state", "created_by"
            ).filter(created_by_id=created_by)
            serializer = ContactInfoSerializer(contactinfos, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, created_by):
        try:
            contactinfos = ContactInfo.objects.filter(created_by_id=created_by)
            if not contactinfos.exists():
                return Response(
                    {"detail": "No ContactInfo found for this user."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Loop through the list of objects to update each individually
            updated_data = []
            for contactinfo in contactinfos:
                serializer = ContactInfoSerializer(
                    contactinfo, data=request.data, partial=True
                )
                serializer.is_valid(raise_exception=True)
                serializer.save()
                updated_data.append(serializer.data)

            return Response(updated_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class CallReportCreateView(BaseTokenView):
    """GET all call report / POST new call report"""

    def get(self, request):
        try:
            call_report = CallReport.objects.select_related("created_by").all()
            serializer = CallReportSerializer(call_report, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # customer_id = request.data.get("Customer")
            # if not customer_id:
            #     return Response(
            #         {"error": "Add Customer Contact first"},
            #         status=status.HTTP_400_BAD_REQUEST
            #     )

            serializer = CallReportSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(created_by=authUser)

            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response(
                {"detail": str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        


class StaffCallSummaryView(BaseTokenView):
    def format_seconds(self, seconds):
        seconds = int(seconds or 0)
        return str(timedelta(seconds=seconds))

    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")

            queryset = CallReport.objects.select_related("created_by")

            if start_date and end_date:
                queryset = queryset.filter(created_at__date__range=[start_date, end_date])
            elif start_date:
                queryset = queryset.filter(created_at__date__gte=start_date)
            elif end_date:
                queryset = queryset.filter(created_at__date__lte=end_date)

            queryset = (
                queryset
                .annotate(
                    duration_clean=Func(
                        'duration',
                        Value('[^0-9]'),
                        Value(''),
                        Value('g'),
                        function='regexp_replace'
                    ),
                    duration_int=Cast('duration_clean', IntegerField())
                )
                .values(
                    'created_by_id',
                    'created_by__name'
                )
                .annotate(
                    productive_calls=Count(
                        Case(
                            When(status='Productive', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    active_calls=Count(
                        Case(
                            When(status='Active', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    total_calls=Count('id'),

                    productive_duration_seconds=Coalesce(
                        Sum(
                            Case(
                                When(status='Productive', then='duration_int'),
                                output_field=IntegerField()
                            )
                        ),
                        0
                    ),
                    active_duration_seconds=Coalesce(
                        Sum(
                            Case(
                                When(status='Active', then='duration_int'),
                                output_field=IntegerField()
                            )
                        ),
                        0
                    ),
                    total_duration_seconds=Coalesce(
                        Sum('duration_int'),
                        0
                    ),
                    total_amount=Coalesce(
                        Sum('amount'),
                        0.0,
                        output_field=FloatField()
                    )
                )
                .order_by('created_by__name')
            )

            summary_data = []
            for item in queryset:
                summary_data.append({
                    "staff_id": item["created_by_id"],
                    "staff_name": item["created_by__name"],
                    "productive_calls": item["productive_calls"] or 0,
                    "active_calls": item["active_calls"] or 0,
                    "total_calls": item["total_calls"] or 0,
                    "productive_call_duration": self.format_seconds(item["productive_duration_seconds"]),
                    "active_call_duration": self.format_seconds(item["active_duration_seconds"]),
                    "total_call_duration": self.format_seconds(item["total_duration_seconds"]),
                    "total_amount": float(item["total_amount"] or 0),
                })

            serializer = StaffCallSummarySerializer(summary_data, many=True)

            return Response(
                {
                    "status": "success",
                    "start_date": start_date,
                    "end_date": end_date,
                    "count": len(serializer.data),
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Failed to fetch staff call summary",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        


class StateWiseCallSummaryView(BaseTokenView):
    def format_seconds(self, seconds):
        seconds = int(seconds or 0)
        return str(timedelta(seconds=seconds))

    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")

            queryset = CallReport.objects.filter(
                Customer__state__isnull=False
            ).select_related("Customer__state")

            if start_date and end_date:
                queryset = queryset.filter(created_at__date__range=[start_date, end_date])
            elif start_date:
                queryset = queryset.filter(created_at__date__gte=start_date)
            elif end_date:
                queryset = queryset.filter(created_at__date__lte=end_date)

            queryset = (
                queryset
                .annotate(
                    duration_clean=Func(
                        'duration',
                        Value('[^0-9]'),
                        Value(''),
                        Value('g'),
                        function='regexp_replace'
                    ),
                    duration_int=Cast('duration_clean', IntegerField())
                )
                .values(
                    'Customer__state_id',
                    'Customer__state__name'
                )
                .annotate(
                    total_calls=Count('id'),
                    active_calls=Count(
                        Case(
                            When(status='Active', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    productive_calls=Count(
                        Case(
                            When(status='Productive', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    active_duration_seconds=Coalesce(
                        Sum(
                            Case(
                                When(status='Active', then='duration_int'),
                                output_field=IntegerField()
                            )
                        ),
                        0
                    ),
                    productive_duration_seconds=Coalesce(
                        Sum(
                            Case(
                                When(status='Productive', then='duration_int'),
                                output_field=IntegerField()
                            )
                        ),
                        0
                    ),
                    total_duration_seconds=Coalesce(
                        Sum('duration_int'),
                        0
                    ),
                    total_amount=Coalesce(
                        Sum('amount'),
                        0.0,
                        output_field=FloatField()
                    )
                )
                .order_by('Customer__state__name')
            )

            summary_data = []
            for item in queryset:
                summary_data.append({
                    "state_id": item["Customer__state_id"],
                    "state_name": item["Customer__state__name"],
                    "active_calls": item["active_calls"] or 0,
                    "productive_calls": item["productive_calls"] or 0,
                    "total_calls": item["total_calls"] or 0,
                    "active_call_duration": self.format_seconds(item["active_duration_seconds"]),
                    "productive_call_duration": self.format_seconds(item["productive_duration_seconds"]),
                    "total_call_duration": self.format_seconds(item["total_duration_seconds"]),
                    "total_amount": float(item["total_amount"] or 0),
                })

            serializer = StateCallSummarySerializer(summary_data, many=True)

            return Response(
                {
                    "status": "success",
                    "start_date": start_date,
                    "end_date": end_date,
                    "count": len(serializer.data),
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Failed to fetch state-wise call summary",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class CallReportUpdateView(BaseTokenView):
    """GET a single call report / PUT update by id"""

    def get(self, request, pk):
        try:
            call_report = get_object_or_404(CallReport.objects.select_related("created_by"), pk=pk)
            serializer = CallReportSerializer(call_report)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    parser_classes = (MultiPartParser, FormParser)

    def put(self, request, pk):
        try:

            call_report = get_object_or_404(CallReport, pk=pk)
            file_obj = request.FILES.get("audio_file", None)

            # Work directly with request.data
            data = request.data

            new_status = data.get("status")
            customer_id = data.get("Customer") or getattr(call_report.Customer, "id", None)

            if new_status == "Productive" and not customer_id:
                return Response(
                    {"error": "Add Customer Contact first"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Do NOT copy or mutate QueryDict directly.
            # Create a shallow dictionary excluding 'audio_file'
            cleaned_data = {k: v for k, v in data.items() if k != "audio_file"}

            serializer = CallReportSerializer(call_report, data=cleaned_data, partial=True)
            serializer.is_valid(raise_exception=True)
            instance = serializer.save()

            # Handle file manually AFTER saving
            if file_obj:
                instance.audio_file.save(file_obj.name, file_obj, save=True)

            return Response(CallReportSerializer(instance).data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        

class CallReportByDateView(BaseTokenView):
   
    def get(self, request, date):
        try:
            try:
                date_obj = datetime.strptime(date, "%Y-%m-%d").date()
            except ValueError:
                return Response(
                    {"error": "Invalid date format. Use YYYY-MM-DD."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            reports = CallReport.objects.filter(created_at__date=date_obj)

            if not reports.exists():
                return Response(
                    {"message": "No call reports found for this date."},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = CallReportSortingSerializer(reports, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class CallReportByStaffView(BaseTokenView):

    def get(self, request, created_by):
        try:
            try:
                user_id = int(created_by)
            except ValueError:
                return Response(
                    {"error": "Invalid user ID. Must be an integer."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            reports = CallReport.objects.filter(created_by_id=user_id).order_by('-created_at')

            if not reports.exists():
                return Response(
                    {"message": "No call reports found for this user."},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = CallReportSortingSerializer(reports, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class CallReportByStateView(BaseTokenView):
    
    def get(self, request, state_id):
        try:
            try:
                state_id = int(state_id)
            except ValueError:
                return Response(
                    {"error": "Invalid state ID. Must be an integer."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            reports = CallReport.objects.filter(Customer__state_id=state_id).select_related("Customer", "created_by").order_by('-created_at')

            if not reports.exists():
                return Response(
                    {"message": "No call reports found for this state."},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = CallReportSortingSerializer(reports, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class CallReportFilterView(BaseTokenView):
    
    def get(self, request):
        try:
            reports = CallReport.objects.select_related("Customer", "created_by")

            customer_name = request.query_params.get("customer_name")
            customer_id = request.query_params.get("customer")

            if customer_id:
                reports = reports.filter(Customer_id=customer_id)

            if customer_name:
                reports = reports.filter(customer_name__icontains=customer_name)

            reports = reports.order_by("-created_at")

            if not reports.exists():
                return Response(
                    {"message": "No call reports found for the given filters."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            serializer = CallReportSortingSerializer(reports, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class CallReportSummaryView(BaseTokenView):
    
    def get(self, request, *args, **kwargs):
        try:
            # Overall totals
            total_count = CallReport.objects.count()
            active_count = CallReport.objects.filter(status='Active').count()
            productive_count = CallReport.objects.filter(status='Productive').count()
            inactive_count = CallReport.objects.filter(status='inactive').count()
            total_amount = CallReport.objects.aggregate(total=Sum('amount'))['total'] or 0

            # Total duration across all reports
            total_seconds = 0
            for report in CallReport.objects.exclude(duration__isnull=True).exclude(duration=''):
                dur = report.duration.lower().strip()
                try:
                    minutes = 0
                    seconds = 0
                    min_match = re.search(r'(\d+)\s*min', dur)
                    sec_match = re.search(r'(\d+)\s*sec', dur)
                    if min_match:
                        minutes = int(min_match.group(1))
                    if sec_match:
                        seconds = int(sec_match.group(1))
                    total_seconds += minutes * 60 + seconds
                except Exception:
                    continue
            total_duration = str(timedelta(seconds=total_seconds))

            # Today
            today = date.today()

            # PRODUCTIVE uses `call_datetime`
            today_productive_qs = CallReport.objects.filter(call_datetime=today, status='Productive')
            today_productive = today_productive_qs.count()

            # ACTIVE uses `call_datetime__date`
            today_active_qs = CallReport.objects.filter(call_datetime__date=today, status='Active')
            today_active = today_active_qs.count()

            # INACTIVE - use call_datetime__date for "today" counts (keeps consistency with Active)
            today_inactive_qs = CallReport.objects.filter(call_datetime__date=today, status__iexact='inactive')
            today_inactive = today_inactive_qs.count()

            # TOTAL for today: combine active + productive + inactive (as counts)
            today_total = today_active + today_productive + today_inactive

            # Amount for today: sum amounts from records considered productive by `date`
            # (If you want amounts from active as well, change accordingly; keeping same approach as earlier)
            today_amount = today_productive_qs.aggregate(total=Sum('amount'))['total'] or 0

            # Duration for today: sum durations from both active (call_datetime) and productive (date)
            today_seconds = 0
            for report in list(today_active_qs) + list(today_productive_qs):
                dur = (report.duration or "").lower().strip()
                try:
                    minutes = 0
                    seconds = 0
                    min_match = re.search(r'(\d+)\s*min', dur)
                    sec_match = re.search(r'(\d+)\s*sec', dur)
                    if min_match:
                        minutes = int(min_match.group(1))
                    if sec_match:
                        seconds = int(sec_match.group(1))
                    today_seconds += minutes * 60 + seconds
                except Exception:
                    continue
            today_duration = str(timedelta(seconds=today_seconds))

            # Current month (productive uses `call_datetime`, active uses created_at)
            month_start = today.replace(day=1)

            month_productive_qs = CallReport.objects.filter(call_datetime__gte=month_start, call_datetime__lte=today, status='Productive')
            month_productive = month_productive_qs.count()

            month_active_qs = CallReport.objects.filter(call_datetime__date__gte=month_start, call_datetime__date__lte=today, status='Active')
            month_active = month_active_qs.count()

            month_inactive_qs = CallReport.objects.filter(call_datetime__date__gte=month_start, call_datetime__date__lte=today, status__iexact='inactive')
            month_inactive = month_inactive_qs.count()

            month_total = month_active + month_productive + month_inactive
            month_amount = month_productive_qs.aggregate(total=Sum('amount'))['total'] or 0

            month_seconds = 0
            for report in list(month_active_qs) + list(month_productive_qs):
                dur = (report.duration or "").lower().strip()
                try:
                    minutes = 0
                    seconds = 0
                    min_match = re.search(r'(\d+)\s*min', dur)
                    sec_match = re.search(r'(\d+)\s*sec', dur)
                    if min_match:
                        minutes = int(min_match.group(1))
                    if sec_match:
                        seconds = int(sec_match.group(1))
                    month_seconds += minutes * 60 + seconds
                except Exception:
                    continue
            month_duration = str(timedelta(seconds=month_seconds))

            # Last 30 days (productive uses `call_datetime`, active uses call_datetime)
            last_30_days = today - timedelta(days=30)

            last30_productive_qs = CallReport.objects.filter(call_datetime__gte=last_30_days, call_datetime__lte=today, status='Productive')
            last30_productive = last30_productive_qs.count()

            last30_active_qs = CallReport.objects.filter(call_datetime__date__gte=last_30_days, call_datetime__date__lte=today, status='Active')
            last30_active = last30_active_qs.count()

            last30_inactive_qs = CallReport.objects.filter(call_datetime__date__gte=last_30_days, call_datetime__date__lte=today, status__iexact='inactive')
            last30_inactive = last30_inactive_qs.count()

            last30_total = last30_active + last30_productive + last30_inactive
            last30_amount = last30_productive_qs.aggregate(total=Sum('amount'))['total'] or 0

            last30_seconds = 0
            for report in list(last30_active_qs) + list(last30_productive_qs):
                dur = (report.duration or "").lower().strip()
                try:
                    minutes = 0
                    seconds = 0
                    min_match = re.search(r'(\d+)\s*min', dur)
                    sec_match = re.search(r'(\d+)\s*sec', dur)
                    if min_match:
                        minutes = int(min_match.group(1))
                    if sec_match:
                        seconds = int(sec_match.group(1))
                    last30_seconds += minutes * 60 + seconds
                except Exception:
                    continue
            last30_duration = str(timedelta(seconds=last30_seconds))

            # Final response
            data = {
                "total_records": total_count,
                "active_count": active_count,
                "productive_count": productive_count,
                "inactive_count": inactive_count,
                "total_amount": round(total_amount, 2),
                "total_duration": total_duration,

                "today_summary": {
                    "date": today.strftime("%Y-%m-%d"),
                    "total_records": today_total,
                    "active_count": today_active,
                    "productive_count": today_productive,
                    "inactive_count": today_inactive,
                    "total_amount": round(today_amount, 2),
                    "total_duration": today_duration,
                },

                "current_month_summary": {
                    "month_start": month_start.strftime("%Y-%m-%d"),
                    "month_end": today.strftime("%Y-%m-%d"),
                    "total_records": month_total,
                    "active_count": month_active,
                    "productive_count": month_productive,
                    "inactive_count": month_inactive,
                    "total_amount": round(month_amount, 2),
                    "total_duration": month_duration,
                },

                "last_30_days_summary": {
                    "from_date": last_30_days.strftime("%Y-%m-%d"),
                    "to_date": today.strftime("%Y-%m-%d"),
                    "total_records": last30_total,
                    "active_count": last30_active,
                    "productive_count": last30_productive,
                    "inactive_count": last30_inactive,
                    "total_amount": round(last30_amount, 2),
                    "total_duration": last30_duration,
                },

                "status": "success"
            }

            return JsonResponse(data, status=200)

        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": str(e)
            }, status=500)


class QuestionnaireView(BaseTokenView):

    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            questionnaires = Questionnaire.objects.all().order_by('-created_at')
            serializer = QuestionnaireSerializer(questionnaires, many=True)

            return Response(
                {"data": serializer.data, "message": "Questionnaires retrieved successfully"},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = QuestionnaireSerializer(data=request.data)
            # will raise ValidationError which DRF will convert to a 400 if unhandled
            serializer.is_valid(raise_exception=True)

            with transaction.atomic():
                instance = serializer.save(created_by=auth_user)

            # re-serialize the saved instance so read-only fields (created_by_name, etc.) exist
            out = QuestionnaireSerializer(instance).data
            return Response({"data": out, "message": "Questionnaire created successfully"},
                            status=status.HTTP_201_CREATED)

        except ValidationError:
            # let DRF handle validation errors (this block is optional if you want custom format)
            raise
        except User.DoesNotExist:
            return Response({"detail": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as exc:
            # unexpected errors -> 500
            return Response({"detail": "An internal error occurred", "error": str(exc)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

class QuestionnaireDetailView(BaseTokenView):

    def get(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                questionnaire = Questionnaire.objects.get(pk=pk)
            except Questionnaire.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Questionnaire not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = QuestionnaireSerializer(questionnaire)
            return Response(
                {"data": serializer.data, "message": "Questionnaire retrieved successfully"},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                questionnaire = Questionnaire.objects.get(pk=pk)
            except Questionnaire.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Questionnaire not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = QuestionnaireSerializer(questionnaire, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"data": serializer.data, "message": "Questionnaire updated successfully"},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "message": "Invalid data", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class AnswersView(BaseTokenView):

    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            answers = Answers.objects.all().order_by('-created_at')
            serializer = AnswersSerializer(answers, many=True)
            return Response(
                {"data": serializer.data, "message": "Answers retrieved successfully"},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            # ✅ Authenticate user from token
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # ✅ Initialize serializer
            serializer = AnswersSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            # ✅ Save with added_by from token, wrapped in transaction for safety
            with transaction.atomic():
                instance = serializer.save(added_by=auth_user)

            # ✅ Re-serialize the saved instance to include read-only fields (like added_by_name)
            out = AnswersSerializer(instance).data

            return Response(
                {"data": out, "message": "Answer created successfully"},
                status=status.HTTP_201_CREATED
            )

        except ValidationError:
            # DRF automatically handles this if you raise it, but you can customize:
            raise
        except User.DoesNotExist:
            return Response(
                {"detail": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"detail": "An internal error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AnswersDetailView(BaseTokenView):

    def get(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                answer = Answers.objects.get(pk=pk)
            except Answers.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Answer not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = AnswersSerializer(answer)
            return Response(
                {"data": serializer.data, "message": "Answer retrieved successfully"},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                answer = Answers.objects.get(pk=pk)
            except Answers.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Answer not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = AnswersSerializer(answer, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {"data": serializer.data, "message": "Answer updated successfully"},
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "message": "Invalid data", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": "An error occurred", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class DistrictView(BaseTokenView):

    def get(self, request):
        try:
            districts = Districts.objects.all()
            serializer = DistrictSerializer(districts, many=True)
            return Response({
                "success": True,
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            serializer = DistrictSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "success": True,
                    "message": "District created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    "success": False,
                    "errors": serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DistrictDetailView(BaseTokenView):

    def get(self, request, id):

        try:
            district = Districts.objects.get(pk=id)
            serializer = DistrictSerializer(district)
            return Response({
                "success": True,
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Districts.DoesNotExist:
            return Response({
                "success": False,
                "error": "District not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def put(self, request, id):

        try:
            district = Districts.objects.get(pk=id)
            serializer = DistrictSerializer(district, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "success": True,
                    "message": "District updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Districts.DoesNotExist:
            return Response({
                "success": False,
                "error": "District not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StaffOrderUpdateView(BaseTokenView):

    def post(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            data = request.data.copy()
            data["staff"] = auth_user.id

            serializer = StaffOrderUpdateSerializer(data=data)

            if not serializer.is_valid():
                return Response(
                    {"error": "Validation failed", "details": serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer.save()

            return Response(
                {"message": "Order update saved successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response(
                {"error": "Something went wrong", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    def get(self, request):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # queryset = StaffOrderUpdate.objects.filter(staff=auth_user).order_by("-id")
            queryset = StaffOrderUpdate.objects.all().order_by("-id")
            serializer = StaffOrderUpdateSerializer(queryset, many=True)

            return Response(
                {"message": "Fetched successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": "Failed to fetch data", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class StaffOrderUpdateDetailView(BaseTokenView):

    def get(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = get_object_or_404(StaffOrderUpdate, pk=pk, staff=auth_user)
            serializer = StaffOrderUpdateSerializer(obj)

            return Response(
                {"message": "Fetched successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": "Failed to fetch data", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            auth_user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = get_object_or_404(StaffOrderUpdate, pk=pk, staff=auth_user)

            data = request.data.copy()  
            data["staff"] = auth_user.id 
            serializer = StaffOrderUpdateSerializer(obj, data=data)
            if serializer.is_valid():

                serializer.save()

                return Response(
                    {"message": "Updated successfully", "data": serializer.data},
                    status=status.HTTP_200_OK
                )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {"error": "Failed to update data", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class CustomerByManagerView(BaseTokenView):

    def get(self, request, manager_id):
        try:
            customers = Customers.objects.filter(manager_id=manager_id)

            serializer = CustomerSerilizers(customers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": "Something went wrong", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
class QuestionnaireByFamilyView(BaseTokenView):

    def get(self, request, family_id):
        try:
            questionnaires = Questionnaire.objects.filter(family_id=family_id)

            serializer = QuestionnaireSerializer(questionnaires, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {
                    "error": "Something went wrong while fetching questionnaires.",
                    "details": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class AnswersByFamilyView(BaseTokenView):

    def get(self, request, family_id):
        try:
            answers = Answers.objects.filter(family_id=family_id)

            serializer = AnswersSerializer(answers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {
                    "error": "Something went wrong while fetching answers.",
                    "details": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RefundReceiptView(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            request.data['created_by'] = authUser.pk

            serializer = RefundReceiptSerializer(data=request.data)
            if serializer.is_valid():
                receipt = serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Refund receipt created successfully",
                        "data": RefundReceiptSerializer(receipt).data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"status": "error", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            receipts = RefundReceipt.objects.all().order_by('-id')
            serializer = RefundReceiptSerializer(receipts, many=True)

            return Response(
                {"status": "success", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "error", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RefundReceiptDetailView(BaseTokenView):
    def get(self, request, pk):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                receipt = RefundReceipt.objects.get(pk=pk)
            except RefundReceipt.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Refund receipt not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = RefundReceiptSerializer(receipt)
            return Response(
                {"status": "success", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "error", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                receipt = RefundReceipt.objects.get(pk=pk)
            except RefundReceipt.DoesNotExist:
                return Response(
                    {"status": "error", "message": "Refund receipt not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = RefundReceiptSerializer(
                receipt,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Refund receipt updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {"status": "error", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {"status": "error", "errors": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


from django.db.models import (
    Count, Sum, Case, When, IntegerField, FloatField, Value, Func
)
from django.db.models.functions import Cast
class FamilyWiseCallReportView(APIView):

    def get_family_queryset(self, base_qs):
        """
        Shared aggregation logic (DOES NOT change existing logic)
        """
        return (
            base_qs
            .annotate(
                duration_clean=Func(
                    'duration',
                    Value('[^0-9]'),
                    Value(''),
                    Value('g'),
                    function='regexp_replace'
                ),
                duration_int=Cast('duration_clean', IntegerField())
            )
            .values(
                'created_by__family__id',
                'created_by__family__name'
            )
            .annotate(
                # -------- TOTAL --------
                total_calls=Count('id'),
                total_duration=Sum('duration_int'),
                total_amount=Sum('amount'),

                # -------- ACTIVE --------
                active_calls=Count(
                    Case(When(status='Active', then=1),
                         output_field=IntegerField())
                ),
                active_duration=Sum(
                    Case(When(status='Active', then='duration_int'),
                         output_field=IntegerField())
                ),
                active_amount=Sum(
                    Case(When(status='Active', then='amount'),
                         output_field=FloatField())
                ),

                # -------- PRODUCTIVE --------
                productive_calls=Count(
                    Case(When(status='Productive', then=1),
                         output_field=IntegerField())
                ),
                productive_duration=Sum(
                    Case(When(status='Productive', then='duration_int'),
                         output_field=IntegerField())
                ),
                productive_amount=Sum(
                    Case(When(status='Productive', then='amount'),
                         output_field=FloatField())
                ),
            )
            .order_by('created_by__family__name')
        )

    def get(self, request):
        try:
            base_qs = CallReport.objects.filter(
                created_by__family__isnull=False,
                call_datetime__isnull=False
            )

            today = now().date()
            last_30_days = now() - timedelta(days=30)

            # ---------------- EXISTING (UNCHANGED) ----------------
            overall_data = self.get_family_queryset(base_qs)

            # ---------------- TODAY ----------------
            today_data = self.get_family_queryset(
                base_qs.filter(call_datetime__date=today)
            )

            # ---------------- THIS MONTH ----------------
            month_data = self.get_family_queryset(
                base_qs.filter(
                    call_datetime__year=today.year,
                    call_datetime__month=today.month
                )
            )

            # ---------------- LAST 30 DAYS ----------------
            last_30_days_data = self.get_family_queryset(
                base_qs.filter(call_datetime__gte=last_30_days)
            )

            return Response(
                {
                    "success": True,
                    "count": len(overall_data),

                    # EXISTING RESPONSE (UNCHANGED)
                    "data": overall_data,

                    # NEW ADDITIONS
                    "today": today_data,
                    "this_month": month_data,
                    "last_30_days": last_30_days_data,
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": "Failed to fetch family-wise call report",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class FamilyUserWiseCallReportView(APIView):

    def get(self, request, family_id, from_date, to_date):
        try:
            queryset = CallReport.objects.filter(
                created_by__family_id=family_id
            )

      
            if from_date and to_date:
                queryset = queryset.filter(
                    call_datetime__date__range=[from_date, to_date]
                )

            data = (
                queryset
                .annotate(
                    duration_clean=Func(
                        'duration',
                        Value('[^0-9]'),
                        Value(''),
                        Value('g'),
                        function='regexp_replace'
                    ),
                    duration_int=Cast('duration_clean', IntegerField())
                )
                .values(
                    'created_by_id',
                    'created_by__name',
                    'created_by__designation'
                )
                .annotate(
                    # ---------------- TOTAL ----------------
                    total_calls=Count('id'),
                    total_duration=Sum('duration_int'),
                    total_amount=Sum('amount'),

                    # ---------------- ACTIVE ----------------
                    active_calls=Count(
                        Case(
                            When(status='Active', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    active_duration=Sum(
                        Case(
                            When(status='Active', then='duration_int'),
                            output_field=IntegerField()
                        )
                    ),
                    active_amount=Sum(
                        Case(
                            When(status='Active', then='amount'),
                            output_field=FloatField()
                        )
                    ),

                    # ---------------- PRODUCTIVE ----------------
                    productive_calls=Count(
                        Case(
                            When(status='Productive', then=1),
                            output_field=IntegerField()
                        )
                    ),
                    productive_duration=Sum(
                        Case(
                            When(status='Productive', then='duration_int'),
                            output_field=IntegerField()
                        )
                    ),
                    productive_amount=Sum(
                        Case(
                            When(status='Productive', then='amount'),
                            output_field=FloatField()
                        )
                    ),
                )
                .order_by('created_by__name')
            )

            return Response(
                {
                    "success": True,
                    "family_id": family_id,
                    "from_date": from_date,
                    "to_date": to_date,
                    "count": len(data),
                    "data": data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": "Failed to fetch user-wise call report",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UpdateOrderCODSplitView(BaseTokenView):
    def patch(self, request, order_id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order = get_object_or_404(Order, pk=order_id)

            serializer = OrderCODSplitUpdateSerializer(
                order,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                serializer.save()

                return Response(
                    {
                        "status": "success",
                        "message": "Box count updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Failed to update box count",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdvanceAmountTransferListCreateView(BaseTokenView):
    parser_classes = [MultiPartParser, FormParser]

    def get(self, request):
        user, error = self.get_user_from_token(request)
        if error:
            return error

        transfers = AdvanceAmountTransfer.objects.all().order_by("-id")
        serializer = AdvanceAmountTransferSerializer(transfers, many=True)
        return Response(
            {"message": "Transfers fetched successfully", "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        user, error = self.get_user_from_token(request)
        if error:
            return error

        serializer = AdvanceAmountTransferSerializer(data=request.data)
        if serializer.is_valid():
            transfer = serializer.save(created_by=user)

            images = request.FILES.getlist("images")
            for img in images:
                AdvanceAmountTransferImage.objects.create(
                    transfer=transfer, image=img
                )

            return Response(
                {
                    "message": "Advance amount transfer created successfully",
                    "data": AdvanceAmountTransferSerializer(transfer).data,
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {"message": "Validation error", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
    
class AdvanceAmountTransferDetailView(BaseTokenView):
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self, pk):
        return get_object_or_404(AdvanceAmountTransfer, pk=pk)

    def get(self, request, pk):
        user, error = self.get_user_from_token(request)
        if error:
            return error

        transfer = self.get_object(pk)
        serializer = AdvanceAmountTransferSerializer(transfer)
        return Response(
            {"message": "Transfer fetched successfully", "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def put(self, request, pk):
        user, error = self.get_user_from_token(request)
        if error:
            return error

        transfer = self.get_object(pk)
        serializer = AdvanceAmountTransferSerializer(
            transfer, data=request.data, partial=True
        )

        if serializer.is_valid():
            serializer.save()

            images = request.FILES.getlist("images")
            for img in images:
                AdvanceAmountTransferImage.objects.create(
                    transfer=transfer, image=img
                )

            return Response(
                {
                    "message": "Transfer updated successfully",
                    "data": AdvanceAmountTransferSerializer(transfer).data,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"message": "Validation error", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

class AdvanceAmountTransferImageDeleteView(BaseTokenView):
    def delete(self, request, image_id):
        user, error = self.get_user_from_token(request)
        if error:
            return error

        image = get_object_or_404(AdvanceAmountTransferImage, pk=image_id)
        image.image.delete(save=False)
        image.delete()

        return Response(
            {"message": "Transfer image deleted successfully"},
            status=status.HTTP_200_OK,
        )


# Bank Account Type Views

class BankAccountTypeView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            queryset = BankAccountType.objects.all().order_by("id")
            serializer = BankAccountTypeSerializer(queryset, many=True)

            return Response({
                "status": "success",
                "message": "Bank account types fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except DatabaseError:
            return Response({
                "status": "error",
                "message": "Database error occurred"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = BankAccountTypeSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "status": "success",
                    "message": "Bank account type created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "status": "error",
                "message": "Validation failed",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class BankAccountTypeDetailView(BaseTokenView):

    def get_object(self, pk):
        return get_object_or_404(BankAccountType, pk=pk)

    def get(self, request, pk):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk)
            serializer = BankAccountTypeSerializer(obj)

            return Response({
                "status": "success",
                "message": "Bank account type fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk)
            serializer = BankAccountTypeSerializer(obj, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "status": "success",
                    "message": "Bank account type updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "status": "error",
                "message": "Validation failed",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk)
            obj.delete()

            return Response({
                "status": "success",
                "message": "Bank account type deleted successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# Reports and Analytics functions only for CRUD operations based on daily sales

class DailySalesReportView(BaseTokenView):
    
    # return logged-in user's created daily sales reports
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            reports = DailySalesReport.objects.filter(user=authUser).order_by("-id")
            serializer = DailySalesReportGETSerializer(reports, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "Daily sales reports fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in DailySalesReportView GET: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # user auto from token
            data = request.data.copy()
            data["user"] = authUser.pk

            serializer = DailySalesReportSerializer(data=data)
            if serializer.is_valid():
                serializer.save()

                return Response(
                    {
                        "status": "success",
                        "message": "Daily sales report created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.exception("Error in DailySalesReportView POST: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class DailySalesReportUpdateView(BaseTokenView):

    def get_object(self, pk):
        return get_object_or_404(DailySalesReport, pk=pk)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk)
            serializer = DailySalesReportGETSerializer(report)

            return Response(
                {
                    "status": "success",
                    "message": "Daily sales report fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Daily Sales Report Update View GET: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk)

            # prevent changing user
            data = request.data.copy()
            data["user"] = report.user.pk

            serializer = DailySalesReportSerializer(report, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()

                return Response(
                    {
                        "status": "success",
                        "message": "Daily sales report updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.exception("Error in DailySalesReportUpdateView PUT: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk)

            # ONLY creator can delete
            if report.user != authUser:
                return Response(
                    {
                        "status": "error",
                        "message": "You are not allowed to delete this report"
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            report.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Daily sales report deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in DailySalesReportUpdateView DELETE: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class DailySalesReportAllView(BaseTokenView):
    
    # return all daily sales reports
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            #  If you want only Admin to access, 
            # currently can't, need to show for Admin, CEO, COO, & Accounts
            # uncomment below
            # if authUser.department_id.name != "Admin":
            #     return Response(
            #         {"status": "error", "message": "Permission denied"},
            #         status=status.HTTP_403_FORBIDDEN
            #     )

            reports = DailySalesReport.objects.all().order_by("-id")
            serializer = DailySalesReportGETSerializer(reports, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "All Daily Sales Reports fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Daily Sales Report All View GET: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BDMBDODailySalesAddReportView(BaseTokenView):
    
    # return logged-in user's(BDM) created daily sales reports
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            reports = BDMBDOReport.objects.filter(bdm=authUser).order_by("-id")
            serializer = BDMBDOReportGETSerializer(reports, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "Daily sales reports fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Report GET: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # user auto from token
            data = request.data.copy()
            data["bdm"] = authUser.pk

            serializer = BDMBDOReportSerializer(data=data)
            if serializer.is_valid():
                serializer.save()

                return Response(
                    {
                        "status": "success",
                        "message": "Daily sales report created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.exception("Error in Report POST: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class BDMBDODailySalesReportView(BaseTokenView):

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # GET ALL REPORTS (No Filter)
            reports = BDMBDOReport.objects.all().order_by("-id")
            serializer = BDMBDOReportGETSerializer(reports, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "All BDM BDO reports fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Report GET: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BDMBDOReportDetailView(BaseTokenView):

    def get(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                report = BDMBDOReport.objects.get(id=id)
            except BDMBDOReport.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "Report not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            serializer = BDMBDOReportGETSerializer(report)

            return Response(
                {
                    "status": "success",
                    "message": "Report fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Report GET by ID: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                report = BDMBDOReport.objects.get(id=id)
            except BDMBDOReport.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "Report not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            data = request.data.copy()

            # IMPORTANT: Do not allow changing bdm from frontend
            data["bdm"] = report.bdm.id

            serializer = BDMBDOReportSerializer(report, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()

                return Response(
                    {
                        "status": "success",
                        "message": "Report updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.exception("Error in Report PUT: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            try:
                report = BDMBDOReport.objects.get(id=id)
            except BDMBDOReport.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "Report not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            report.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Report deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.exception("Error in Report DELETE: %s", str(e))
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class SalesAnalysisListCreateView(BaseTokenView):

    def duration_to_seconds(self, duration):
        if not duration:
            return 0
        try:
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def get_average_call_duration(self, durations):
        total_seconds = 0
        count = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)
                count += 1

        if count == 0:
            return 0

        average_seconds = total_seconds / count
        average_minutes = average_seconds / 60

        return round(average_minutes, 2)

    def get_call_duration_percentage_8hrs(self, durations, total_days):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        if total_days <= 0:
            return 0

        total_available_seconds = total_days * 8 * 60 * 60  # 8 hours per day

        if total_available_seconds == 0:
            return 0

        percentage = (total_seconds / total_available_seconds) * 100
        return round(percentage, 2)

    def add_call_durations(self, durations):
        total_hours = 0
        total_minutes = 0
        total_seconds = 0

        for duration in durations:
            if duration:
                try:
                    h, m, s = map(int, str(duration).split(":"))
                    total_hours += h
                    total_minutes += m
                    total_seconds += s
                except:
                    pass

        total_minutes += total_seconds // 60
        total_seconds = total_seconds % 60

        total_hours += total_minutes // 60
        total_minutes = total_minutes % 60

        return f"{total_hours:02}:{total_minutes:02}:{total_seconds:02}"

    def get(self, request, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            search = request.GET.get("search", "").strip()
            call_status_filter = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            customer_filter = request.GET.get("customer", "").strip()
            state_filter = request.GET.get("state", "").strip()
            district_filter = request.GET.get("district", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            sales_data = SalesAnalysis.objects.select_related(
                "customer",
                "invoice",
                "state",
                "district",
                "created_by",
            ).filter(
                created_by=user
            ).order_by("-created_at")

            # Search
            if search:
                if search.isdigit():
                    sales_data = sales_data.filter(
                        Q(invoice__invoice__iregex=rf"{re.escape(search)}$") |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(note__icontains=search) |
                        Q(id=search)
                    )
                else:
                    sales_data = sales_data.filter(
                        Q(invoice__invoice__icontains=search) |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(state__name__icontains=search) |
                        Q(district__name__icontains=search) |
                        Q(call_status__icontains=search) |
                        Q(status__icontains=search) |
                        Q(note__icontains=search)
                    )

            # Filters
            if call_status_filter:
                sales_data = sales_data.filter(call_status__iexact=call_status_filter)

            if status_filter:
                sales_data = sales_data.filter(status__iexact=status_filter)

            if customer_filter:
                sales_data = sales_data.filter(
                    Q(customer__name__icontains=customer_filter) |
                    Q(customer_name__icontains=customer_filter)
                )

            if state_filter:
                sales_data = sales_data.filter(state__name__icontains=state_filter)

            if district_filter:
                sales_data = sales_data.filter(district__name__icontains=district_filter)

            if start_date:
                sales_data = sales_data.filter(created_at__date__gte=start_date)

            if end_date:
                sales_data = sales_data.filter(created_at__date__lte=end_date)

            # Counts before pagination
            summary_counts = sales_data.aggregate(
                active_count=Count("id", filter=Q(call_status="active")),
                productive_count=Count("id", filter=Q(call_status="productive")),
                dsr_created_count=Count("id", filter=Q(status="dsr created")),
                dsr_approved_count=Count("id", filter=Q(status="dsr approved")),
                dsr_confirmed_count=Count("id", filter=Q(status="dsr confirmed")),
                dsr_rejected_count=Count("id", filter=Q(status="dsr rejected")),
                total_invoice_amount=Coalesce(Sum("invoice__total_amount"), 0.0),
            )

            call_durations = list(sales_data.values_list("call_duration", flat=True))

            if start_date and end_date:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                total_days = (end - start).days + 1
            else:
                unique_days = sales_data.values_list("created_at__date", flat=True).distinct()
                total_days = len(unique_days)

            total_call_duration = self.add_call_durations(call_durations)
            average_call_duration = self.get_average_call_duration(call_durations)
            call_duration_percentage_8hrs = self.get_call_duration_percentage_8hrs(
                call_durations,
                total_days
            )


            # Pagination
            paginator = StandardPagination()
            paginated_sales_data = paginator.paginate_queryset(sales_data, request)
            serializer = SalesAnalysisSerializer(paginated_sales_data, many=True)

            return paginator.get_paginated_response({
                "message": "Sales analysis data fetched successfully",
                "count": sales_data.count(),
                "active_count": summary_counts["active_count"],
                "productive_count": summary_counts["productive_count"],
                "dsr_created_count": summary_counts["dsr_created_count"],
                "dsr_approved_count": summary_counts["dsr_approved_count"],
                "dsr_confirmed_count": summary_counts["dsr_confirmed_count"],
                "dsr_rejected_count": summary_counts["dsr_rejected_count"],
                "total_call_duration": total_call_duration,
                "average_call_duration": average_call_duration,
                "call_duration_percentage_8hrs": call_duration_percentage_8hrs,
                "total_invoice_amount": float(summary_counts["total_invoice_amount"]),
                "results": serializer.data
            })

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Sales analysis data not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            data = request.data.copy()
            data["created_by"] = user.id

            call_status = data.get("call_status")
            customer_id = data.get("customer")
            invoice_id = data.get("invoice")

            if call_status == "productive":
                if not customer_id:
                    return Response(
                        {"error": "customer is required when call_status is productive"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if not invoice_id:
                    return Response(
                        {"error": "invoice is required when call_status is productive"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if customer_id:
                try:
                    customer_obj = Customers.objects.get(id=customer_id)
                    data["customer_name"] = customer_obj.name
                except Customers.DoesNotExist:
                    return Response(
                        {"error": "Customer not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            if invoice_id:
                try:
                    Order.objects.get(id=invoice_id)
                except Order.DoesNotExist:
                    return Response(
                        {"error": "Invoice not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            serializer = AddSalesAnalysisSerializer(data=data)
            if serializer.is_valid():
                serializer.save(created_by=user)
                return Response(
                    {
                        "message": "Sales analysis created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(
                {"error": f"Something went wrong: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class SalesAnalysisDetailView(BaseTokenView):

    def get_object(self, pk):
        return SalesAnalysis.objects.get(id=pk)

    def get_user_object(self, pk, user):
        return SalesAnalysis.objects.get(id=pk, created_by=user)

    def get(self, request, pk, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            sales_obj = self.get_object(pk)
            serializer = SalesAnalysisSerializer(sales_obj)

            return Response(
                {
                    "message": "Sales analysis fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except SalesAnalysis.DoesNotExist:
            return Response(
                {"error": "Sales analysis not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"error": f"Something went wrong while fetching data: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            sales_obj = self.get_user_object(pk, user)
            data = request.data.copy()

            allowed_fields = ['customer', 'call_status', 'invoice', 'phone']
            cleaned_data = {key: data.get(key) for key in allowed_fields if key in data}

            call_status = cleaned_data.get("call_status", sales_obj.call_status)
            customer_id = cleaned_data.get("customer", sales_obj.customer.id if sales_obj.customer else None)
            invoice_id = cleaned_data.get("invoice", sales_obj.invoice.id if sales_obj.invoice else None)
            phone = cleaned_data.get("phone", sales_obj.phone)

            if call_status == "productive":
                if not customer_id:
                    return Response(
                        {"error": "customer is required when call_status is productive"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                if not invoice_id:
                    return Response(
                        {"error": "invoice is required when call_status is productive"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if 'customer' in cleaned_data and cleaned_data['customer']:
                try:
                    customer_obj = Customers.objects.get(id=cleaned_data['customer'])
                    cleaned_data['customer_name'] = customer_obj.name
                except Customers.DoesNotExist:
                    return Response(
                        {"error": "Customer not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            if 'invoice' in cleaned_data and cleaned_data['invoice']:
                try:
                    Order.objects.get(id=cleaned_data['invoice'])
                except Order.DoesNotExist:
                    return Response(
                        {"error": "Invoice not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            serializer = AddSalesAnalysisSerializer(sales_obj, data=cleaned_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "message": "Sales analysis updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except SalesAnalysis.DoesNotExist:
            return Response(
                {"error": "Sales analysis not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"error": f"Something went wrong while updating data: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def patch(self, request, pk, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            sales_obj = self.get_object(pk)

            new_status = request.data.get('status')
            if not new_status:
                return Response(
                    {"error": "status is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            valid_statuses = [choice[0] for choice in SalesAnalysis.STATUS_CHOICES]
            if new_status not in valid_statuses:
                return Response(
                    {
                        "error": "Invalid status",
                        "valid_statuses": valid_statuses
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            sales_obj.status = new_status
            sales_obj.save()

            serializer = AddSalesAnalysisSerializer(sales_obj)
            return Response(
                {
                    "message": "Status updated successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except SalesAnalysis.DoesNotExist:
            return Response(
                {"error": "Sales analysis not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"error": f"Something went wrong while patching status: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk, *args, **kwargs):
        try:
            user, error = self.get_user_from_token(request)
            if error:
                return error

            sales_obj = self.get_user_object(pk, user)
            sales_obj.delete()

            return Response(
                {"message": "Sales analysis deleted successfully"},
                status=status.HTTP_200_OK
            )

        except SalesAnalysis.DoesNotExist:
            return Response(
                {"error": "Sales analysis not found or you are not authorized to delete it"},
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"error": f"Something went wrong while deleting data: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SalesAnalysisListView(BaseTokenView):

    def duration_to_seconds(self, duration):
        if not duration:
            return 0
        try:
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0
    
    def get_call_duration_average_8hrs(self, durations):
        total_seconds = 0
        for duration in durations:
            total_seconds += self.duration_to_seconds(duration)

        total_minutes = total_seconds / 60
        average_ratio = total_minutes / (8 * 60)  # 480 minutes = 8 hours
        average_percentage = average_ratio * 100

        return round(average_percentage, 2)

    def add_call_durations(self, durations):
        total_hours = 0
        total_minutes = 0
        total_seconds = 0

        for duration in durations:
            if duration:
                try:
                    h, m, s = map(int, str(duration).split(":"))
                    total_hours += h
                    total_minutes += m
                    total_seconds += s
                except:
                    pass

        # normalize seconds -> minutes
        total_minutes += total_seconds // 60
        total_seconds = total_seconds % 60

        # normalize minutes -> hours
        total_hours += total_minutes // 60
        total_minutes = total_minutes % 60

        return f"{total_hours:02}:{total_minutes:02}:{total_seconds:02}"


    def get_call_duration_percentage_8hrs(self, durations, total_days):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        if total_days <= 0:
            return 0

        total_available_seconds = total_days * 8 * 60 * 60  # 8 hours per day

        if total_available_seconds == 0:
            return 0

        percentage = (total_seconds / total_available_seconds) * 100
        return round(percentage, 2)
    

    def get(self, request, *args, **kwargs):
        try:
            search = request.GET.get("search", "").strip()
            call_status_filter = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            customer_filter = request.GET.get("customer", "").strip()
            state_filter = request.GET.get("state", "").strip()
            district_filter = request.GET.get("district", "").strip()
            created_by_filter = request.GET.get("created_by", "").strip()
            family_filter = request.GET.get("family", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            sales_analysis = SalesAnalysis.objects.select_related(
                "customer",
                "invoice",
                "state",
                "district",
                "created_by",
                "created_by__family",
            ).order_by("-created_at")

            # Search
            if search:
                if search.isdigit():
                    sales_analysis = sales_analysis.filter(
                        Q(id=search) |
                        Q(invoice__invoice__iregex=rf"{re.escape(search)}$") |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(note__icontains=search) |
                        Q(created_by__name__icontains=search) |
                        Q(created_by__family__name__icontains=search)
                    )
                else:
                    sales_analysis = sales_analysis.filter(
                        Q(invoice__invoice__icontains=search) |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(state__name__icontains=search) |
                        Q(district__name__icontains=search) |
                        Q(created_by__name__icontains=search) |
                        Q(created_by__family__name__icontains=search) |
                        Q(call_status__icontains=search) |
                        Q(status__icontains=search) |
                        Q(note__icontains=search)
                    )

            # Filters
            if call_status_filter:
                sales_analysis = sales_analysis.filter(call_status__iexact=call_status_filter)

            if status_filter:
                sales_analysis = sales_analysis.filter(status__iexact=status_filter)

            if customer_filter:
                sales_analysis = sales_analysis.filter(
                    Q(customer__name__icontains=customer_filter) |
                    Q(customer_name__icontains=customer_filter)
                )

            if state_filter:
                sales_analysis = sales_analysis.filter(state__name__icontains=state_filter)

            if district_filter:
                sales_analysis = sales_analysis.filter(district__name__icontains=district_filter)

            if created_by_filter:
                sales_analysis = sales_analysis.filter(created_by__name__icontains=created_by_filter)

            if family_filter:
                if family_filter.isdigit():
                    sales_analysis = sales_analysis.filter(created_by__family_id=family_filter)
                else:
                    sales_analysis = sales_analysis.filter(created_by__family__name__icontains=family_filter)

            if start_date:
                sales_analysis = sales_analysis.filter(created_at__date__gte=start_date)

            if end_date:
                sales_analysis = sales_analysis.filter(created_at__date__lte=end_date)

            # Counts before pagination
            summary_counts = sales_analysis.aggregate(
                total_count=Count("id"),
                active_count=Count("id", filter=Q(call_status="active")),
                productive_count=Count("id", filter=Q(call_status="productive")),
                dsr_created_count=Count("id", filter=Q(status="dsr created")),
                dsr_approved_count=Count("id", filter=Q(status="dsr approved")),
                dsr_confirmed_count=Count("id", filter=Q(status="dsr confirmed")),
                dsr_rejected_count=Count("id", filter=Q(status="dsr rejected")),
                total_invoice_amount=Coalesce(Sum("invoice__total_amount"), 0.0),
            )

            # total call duration based on applied filters
            total_call_duration = self.add_call_durations(
                sales_analysis.values_list("call_duration", flat=True)
            )

            call_durations = list(sales_analysis.values_list("call_duration", flat=True))

            if start_date and end_date:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                total_days = (end - start).days + 1
            else:
                unique_days = sales_analysis.values_list("created_at__date", flat=True).distinct()
                total_days = len(unique_days)

            call_duration_average_8hrs = self.get_call_duration_average_8hrs(call_durations)
            call_duration_percentage_8hrs = self.get_call_duration_percentage_8hrs(
                call_durations,
                total_days
            )

    
            paginator = StandardPagination()
            paginated_sales_analysis = paginator.paginate_queryset(sales_analysis, request)
            serializer = SalesAnalysisSerializer(paginated_sales_analysis, many=True)

            return paginator.get_paginated_response({
                "message": "Sales analysis fetched successfully",
                "count": summary_counts["total_count"],
                "active_count": summary_counts["active_count"],
                "productive_count": summary_counts["productive_count"],
                "dsr_created_count": summary_counts["dsr_created_count"],
                "dsr_approved_count": summary_counts["dsr_approved_count"],
                "dsr_confirmed_count": summary_counts["dsr_confirmed_count"],
                "dsr_rejected_count": summary_counts["dsr_rejected_count"],
                "total_call_duration": total_call_duration,
                "total_invoice_amount": float(summary_counts["total_invoice_amount"]),
                "total_call_duration": total_call_duration,
                "call_duration_average_8hrs": call_duration_average_8hrs,
                "call_duration_percentage_8hrs": call_duration_percentage_8hrs,
                "results": serializer.data
            })

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Sales analysis not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": f"Something went wrong: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class SalesAnalysisByFamilyView(BaseTokenView):

    def duration_to_seconds(self, duration):
        if not duration:
            return 0
        try:
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def seconds_to_hms(self, total_seconds):
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def get_average_call_duration(self, durations):
        total_seconds = 0
        count = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)
                count += 1

        if count == 0:
            return 0

        average_seconds = total_seconds / count
        average_minutes = average_seconds / 60

        return round(average_minutes, 2)

    def add_call_durations(self, durations):
        total_hours = 0
        total_minutes = 0
        total_seconds = 0

        for duration in durations:
            if duration:
                try:
                    h, m, s = map(int, str(duration).split(":"))
                    total_hours += h
                    total_minutes += m
                    total_seconds += s
                except:
                    pass

        total_minutes += total_seconds // 60
        total_seconds = total_seconds % 60

        total_hours += total_minutes // 60
        total_minutes = total_minutes % 60

        return f"{total_hours:02}:{total_minutes:02}:{total_seconds:02}"


    def get_call_duration_percentage_8hrs(self, durations, total_days):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        if total_days <= 0:
            return 0

        total_available_seconds = total_days * 8 * 60 * 60  # 8 hours per day

        if total_available_seconds == 0:
            return 0

        percentage = (total_seconds / total_available_seconds) * 100
        return round(percentage, 2)

    def get(self, request, family_id, *args, **kwargs):
        try:
            search = request.GET.get("search", "").strip()
            call_status_filter = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            customer_filter = request.GET.get("customer", "").strip()
            state_filter = request.GET.get("state", "").strip()
            district_filter = request.GET.get("district", "").strip()
            created_by_filter = request.GET.get("created_by", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            sales_analysis = SalesAnalysis.objects.select_related(
                "customer",
                "invoice",
                "state",
                "district",
                "created_by",
                "created_by__family",
                "created_by__supervisor_id",
            ).filter(
                created_by__family_id=family_id
            ).order_by("-created_at")

            # Search
            if search:
                if search.isdigit():
                    sales_analysis = sales_analysis.filter(
                        Q(id=search) |
                        Q(invoice__invoice__iregex=rf"{re.escape(search)}$") |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(note__icontains=search)
                    )
                else:
                    sales_analysis = sales_analysis.filter(
                        Q(invoice__invoice__icontains=search) |
                        Q(customer__name__icontains=search) |
                        Q(customer_name__icontains=search) |
                        Q(state__name__icontains=search) |
                        Q(district__name__icontains=search) |
                        Q(created_by__name__icontains=search) |
                        Q(call_status__icontains=search) |
                        Q(status__icontains=search) |
                        Q(note__icontains=search)
                    )

            # Filters
            if call_status_filter:
                sales_analysis = sales_analysis.filter(call_status__iexact=call_status_filter)

            if status_filter:
                sales_analysis = sales_analysis.filter(status__iexact=status_filter)

            if customer_filter:
                sales_analysis = sales_analysis.filter(
                    Q(customer__name__icontains=customer_filter) |
                    Q(customer_name__icontains=customer_filter)
                )

            if state_filter:
                sales_analysis = sales_analysis.filter(state__name__icontains=state_filter)

            if district_filter:
                sales_analysis = sales_analysis.filter(district__name__icontains=district_filter)

            if created_by_filter:
                sales_analysis = sales_analysis.filter(created_by_id=created_by_filter)

            if start_date:
                sales_analysis = sales_analysis.filter(created_at__date__gte=start_date)

            if end_date:
                sales_analysis = sales_analysis.filter(created_at__date__lte=end_date)

            summary_counts = sales_analysis.aggregate(
                total_count=Count("id"),
                active_count=Count("id", filter=Q(call_status="active")),
                productive_count=Count("id", filter=Q(call_status="productive")),
                dsr_created_count=Count("id", filter=Q(status="dsr created")),
                dsr_approved_count=Count("id", filter=Q(status="dsr approved")),
                dsr_confirmed_count=Count("id", filter=Q(status="dsr confirmed")),
                dsr_rejected_count=Count("id", filter=Q(status="dsr rejected")),
                total_invoice_amount=Coalesce(Sum("invoice__total_amount"), 0.0),
            )

            call_durations = list(sales_analysis.values_list("call_duration", flat=True))

            if start_date and end_date:
                start = datetime.strptime(start_date, "%Y-%m-%d").date()
                end = datetime.strptime(end_date, "%Y-%m-%d").date()
                total_days = (end - start).days + 1
            else:
                unique_days = sales_analysis.values_list("created_at__date", flat=True).distinct()
                total_days = len(unique_days)

            call_duration_percentage_8hrs = self.get_call_duration_percentage_8hrs(
                call_durations,
                total_days
            )

            total_call_duration = self.add_call_durations(call_durations)
            average_call_duration = self.get_average_call_duration(call_durations)


            paginator = StandardPagination()
            paginated_sales_analysis = paginator.paginate_queryset(sales_analysis, request)
            serializer = SalesAnalysisSerializer(paginated_sales_analysis, many=True)

            return paginator.get_paginated_response({
                "message": "Sales analysis fetched successfully by family",
                "family_id": family_id,
                "count": summary_counts["total_count"],
                "active_count": summary_counts["active_count"],
                "productive_count": summary_counts["productive_count"],
                "dsr_created_count": summary_counts["dsr_created_count"],
                "dsr_approved_count": summary_counts["dsr_approved_count"],
                "dsr_confirmed_count": summary_counts["dsr_confirmed_count"],
                "dsr_rejected_count": summary_counts["dsr_rejected_count"],
                "total_call_duration": total_call_duration,
                "average_call_duration": average_call_duration,
                "call_duration_percentage_8hrs": call_duration_percentage_8hrs,
                "total_invoice_amount": float(summary_counts["total_invoice_amount"]),
                "results": serializer.data
            })

        except ObjectDoesNotExist:
            return Response(
                {"status": "error", "message": "Sales analysis not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        except DatabaseError:
            return Response(
                {"status": "error", "message": "Database error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {"status": "error", "message": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class BDMOrderAnalysisView(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            attendance_date = request.GET.get('attendance_date')

            queryset = BDMOrderAnalysisData.objects.filter(
                created_by=authUser
            ).prefetch_related('staff_entries__staff').order_by('-attendance_date', '-id')

            if attendance_date:
                queryset = queryset.filter(attendance_date=attendance_date)

            serializer = BDMOrderAnalysisDataSerializer(queryset, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "BDM order analysis fetched successfully",
                    "count": queryset.count(),
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching BDM order analysis",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = BDMOrderAnalysisDataSerializer(
                data=request.data,
                context={'created_by': authUser}
            )

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "BDM order analysis created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while creating BDM order analysis",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BDMOrderAnalysisDetailView(BaseTokenView):
    def get_object(self, authUser, pk):
        return get_object_or_404(
            BDMOrderAnalysisData.objects.prefetch_related('staff_entries__staff'),
            pk=pk,
            created_by=authUser
        )

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(authUser, pk)
            serializer = BDMOrderAnalysisDataSerializer(obj)

            return Response(
                {
                    "status": "success",
                    "message": "BDM order analysis fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching BDM order analysis detail",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(authUser, pk)

            serializer = BDMOrderAnalysisDataSerializer(
                obj,
                data=request.data,
                context={'created_by': authUser}
            )

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "BDM order analysis updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating BDM order analysis",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            staff_id = request.data.get("staff_id")

            if staff_id:
                staff_entry = get_object_or_404(
                    BDMOrderAnalysisStaff.objects.select_related('analysis'),
                    pk=staff_id,
                    analysis__pk=pk,
                    analysis__created_by=authUser
                )
                staff_entry.delete()

                return Response(
                    {
                        "status": "success",
                        "message": "BDM order analysis staff entry deleted successfully"
                    },
                    status=status.HTTP_200_OK
                )

            obj = self.get_object(authUser, pk)
            obj.delete()

            return Response(
                {
                    "status": "success",
                    "message": "BDM order analysis deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while deleting",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class BDMOrderAnalysisStaffFilterView(APIView):
    def get(self, request, *args, **kwargs):
        family_id = request.GET.get('family_id')
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        status_param = request.GET.get('status')

        queryset = BDMOrderAnalysisStaff.objects.select_related(
            'staff',
            'staff__family',
            'analysis'
        ).all()

        if family_id:
            queryset = queryset.filter(staff__family_id=family_id)

        try:
            if start_date:
                start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                queryset = queryset.filter(
                    analysis__attendance_date__gte=start_date_obj
                )

            if end_date:
                end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                queryset = queryset.filter(
                    analysis__attendance_date__lte=end_date_obj
                )
        except ValueError:
            return Response(
                {
                    "status": "error",
                    "message": "Invalid date format. Use YYYY-MM-DD"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if status_param:
            queryset = queryset.filter(status=status_param)

        serializer = BDMOrderAnalysisStaffFilterSerializer(queryset, many=True)

        return Response(
            {
                "status": "success",
                "family_id": family_id,
                "count": queryset.count(),
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )
    

class BdmOrderSelectionView(BaseTokenView):

    pagination_class = StandardPagination

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get('search', '').strip()
            bdm_id = request.GET.get('bdm', '').strip()
            start_date = request.GET.get('start_date', '').strip()
            end_date = request.GET.get('end_date', '').strip()

            queryset = BdmOrderSelection.objects.filter(
                created_by=authUser
            ).select_related(
                'bdm',
                'created_by'
            ).prefetch_related(
                'items__order'
            ).order_by('-created_at')

            if bdm_id:
                queryset = queryset.filter(bdm_id=bdm_id)

            if search:
                queryset = queryset.filter(
                    Q(items__order__invoice__icontains=search)
                )

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                queryset = queryset.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                queryset = queryset.filter(created_at__date__lte=parsed_end_date)

            queryset = queryset.distinct()

            paginator = self.pagination_class()
            paginated_queryset = paginator.paginate_queryset(queryset, request)
            serializer = BdmOrderSelectionSerializer(paginated_queryset, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Bdm order selections fetched successfully",
                "count": queryset.count(),
                "data": serializer.data
            })

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching Bdm order selections",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = BdmOrderSelectionSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(created_by=authUser)
                return Response(
                    {
                        "status": "success",
                        "message": "Bdm order selection created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while creating Bdm order selection",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BdmOrderSelectionDetailView(BaseTokenView):

    def get_object(self, pk, user):
        return get_object_or_404(BdmOrderSelection, pk=pk, created_by=user)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk, authUser)
            serializer = BdmOrderSelectionSerializer(obj)

            return Response(
                {
                    "status": "success",
                    "message": "Bdm order selection fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching Bdm order selection",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk, authUser)
            serializer = BdmOrderSelectionSerializer(obj, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Bdm order selection updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating Bdm order selection",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            obj = self.get_object(pk, authUser)
            obj.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Bdm order selection deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while deleting Bdm order selection",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



# BdmDailyOverallReportView ....

def parse_duration_to_seconds(duration_str):
    """
    Converts duration string like:
    'HH:MM:SS'
    'MM:SS'
    'SS'
    to total seconds
    """
    if not duration_str:
        return 0

    try:
        parts = duration_str.split(":")
        parts = [int(p) for p in parts]

        if len(parts) == 3:
            hours, minutes, seconds = parts
            return hours * 3600 + minutes * 60 + seconds
        elif len(parts) == 2:
            minutes, seconds = parts
            return minutes * 60 + seconds
        elif len(parts) == 1:
            return parts[0]
        return 0
    except:
        return 0


def format_seconds_to_hhmmss(total_seconds):
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02}:{minutes:02}:{seconds:02}"



class BdmDailyOverCreatedReportView(BaseTokenView):
    """
    Date-wise BDM overall report
    Filtered by logged-in user through created_by
    Shows all attendance dates of logged-in user
    """

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")
            bdm_id = request.GET.get("bdm")

            analysis_queryset = BDMOrderAnalysisData.objects.filter(
                created_by=authUser
            )

            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                    analysis_queryset = analysis_queryset.filter(attendance_date__gte=start_date_obj)
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                    analysis_queryset = analysis_queryset.filter(attendance_date__lte=end_date_obj)
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if bdm_id:
                try:
                    bdm_id = int(bdm_id)
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "bdm must be a valid integer id"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            analysis_dates = analysis_queryset.values_list(
                'attendance_date', flat=True
            ).distinct().order_by('-attendance_date')

            if not analysis_dates:
                return Response(
                    {
                        "status": "success",
                        "message": "No BDM data found",
                        "count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK
                )

            response_data = []

            for created_date in analysis_dates:
                attendance_qs = BDMOrderAnalysisStaff.objects.filter(
                    analysis__created_by=authUser,
                    analysis__attendance_date=created_date
                )

                if bdm_id:
                    attendance_qs = attendance_qs.filter(staff_id=bdm_id)

                bdo_present_count = attendance_qs.filter(status='present').count()
                bdo_absent_count = attendance_qs.filter(status='absent').count()
                bdo_half_day_count = attendance_qs.filter(status='half_day').count()

                selections = BdmOrderSelection.objects.filter(
                    created_by=authUser,
                    created_at__date=created_date
                ).select_related('bdm', 'bdm__family').order_by('-created_at')

                if bdm_id:
                    selections = selections.filter(bdm_id=bdm_id)

                bdm_map = {}

                for selection in selections:
                    bdm = selection.bdm
                    current_bdm_id = bdm.id
                    family = getattr(bdm, 'family', None)

                    if current_bdm_id not in bdm_map:
                        bdm_map[current_bdm_id] = {
                            "bdm_id": bdm.id,
                            "bdm_name": getattr(bdm, "name", str(bdm)),
                            "family_id": family.id if family else None,
                            "family_name": family.name if family else "No Family",
                            "selection_ids": [],
                            "total_bill": 0,
                            "total_order_count": 0,
                            "total_volume": 0.0,
                            "total_call_duration_seconds": 0,
                        }

                    bdm_map[current_bdm_id]["selection_ids"].append(selection.id)

                for current_bdm_id, bdm_row in bdm_map.items():
                    selection_ids = bdm_row["selection_ids"]

                    items = BdmOrderSelectionItem.objects.filter(
                        selection_id__in=selection_ids
                    ).select_related('order')

                    bdm_row["total_bill"] = items.count()
                    bdm_row["total_order_count"] = items.count()

                    total_volume = Decimal("0.0")
                    for item in items:
                        if item.order and item.order.total_amount:
                            total_volume += Decimal(str(item.order.total_amount))

                    bdm_row["total_volume"] = float(total_volume)

                for current_bdm_id, bdm_row in bdm_map.items():
                    sales_entries = SalesAnalysis.objects.filter(
                        created_by_id=current_bdm_id,
                        created_at__date=created_date
                    ).exclude(status='dsr rejected')

                    total_seconds = 0
                    for sale in sales_entries:
                        if sale.call_duration:
                            total_seconds += parse_duration_to_seconds(sale.call_duration)

                    bdm_row["total_call_duration_seconds"] = total_seconds

                family_map = {}

                for _, bdm_row in bdm_map.items():
                    family_id = bdm_row["family_id"]
                    family_name = bdm_row["family_name"]

                    if family_id not in family_map:
                        family_map[family_id] = {
                            "family_id": family_id,
                            "family_name": family_name,
                            "bdm_count": 0,
                            "total_bill": 0,
                            "total_order_count": 0,
                            "total_volume": 0.0,
                            "total_call_duration_seconds": 0,
                            "bdm_data": []
                        }

                    bdm_call_duration_minutes = bdm_row["total_call_duration_seconds"] / 60
                    bdm_call_duration_average = round(
                        (bdm_call_duration_minutes / (8 * 60)) * 100, 2
                    ) if bdm_call_duration_minutes > 0 else 0.0

                    bdm_average_call_duration_minutes = round(
                        bdm_call_duration_minutes / bdm_row["total_bill"], 2
                    ) if bdm_row["total_bill"] > 0 else 0.0

                    family_map[family_id]["bdm_count"] += 1
                    family_map[family_id]["total_bill"] += bdm_row["total_bill"]
                    family_map[family_id]["total_order_count"] += bdm_row["total_order_count"]
                    family_map[family_id]["total_volume"] += bdm_row["total_volume"]
                    family_map[family_id]["total_call_duration_seconds"] += bdm_row["total_call_duration_seconds"]

                    family_map[family_id]["bdm_data"].append({
                        "bdm_id": bdm_row["bdm_id"],
                        "bdm_name": bdm_row["bdm_name"],
                        "total_bill": bdm_row["total_bill"],
                        "total_order_count": bdm_row["total_order_count"],
                        "total_volume": round(bdm_row["total_volume"], 2),
                        "total_call_duration": format_seconds_to_hhmmss(
                            bdm_row["total_call_duration_seconds"]
                        ),
                        "call_duration_average": bdm_call_duration_average,
                        "average_call_duration_minutes": bdm_average_call_duration_minutes,
                    })

                family_data = []
                overall_total_bill = 0
                overall_total_volume = 0.0
                overall_total_call_duration_seconds = 0

                for _, family_row in family_map.items():
                    family_row["bdm_data"] = sorted(
                        family_row["bdm_data"],
                        key=lambda x: x["bdm_id"],
                        reverse=True
                    )

                    family_call_duration_minutes = family_row["total_call_duration_seconds"] / 60
                    family_call_duration_average = round(
                        (family_call_duration_minutes / (8 * 60)) * 100, 2
                    ) if family_call_duration_minutes > 0 else 0.0

                    family_average_call_duration_minutes = round(
                        family_call_duration_minutes / family_row["total_bill"], 2
                    ) if family_row["total_bill"] > 0 else 0.0

                    family_data.append({
                        "family_id": family_row["family_id"],
                        "family_name": family_row["family_name"],
                        "bdm_count": family_row["bdm_count"],
                        "total_bill": family_row["total_bill"],
                        "total_order_count": family_row["total_order_count"],
                        "total_volume": round(family_row["total_volume"], 2),
                        "total_call_duration": format_seconds_to_hhmmss(
                            family_row["total_call_duration_seconds"]
                        ),
                        "call_duration_average": family_call_duration_average,
                        "average_call_duration_minutes": family_average_call_duration_minutes,
                        "bdm_data": family_row["bdm_data"]
                    })

                    overall_total_bill += family_row["total_bill"]
                    overall_total_volume += family_row["total_volume"]
                    overall_total_call_duration_seconds += family_row["total_call_duration_seconds"]

                family_data = sorted(
                    family_data,
                    key=lambda x: (x["family_name"] or "").lower()
                )

                total_call_duration_minutes = overall_total_call_duration_seconds / 60
                overall_call_duration_average = round(
                    (total_call_duration_minutes / (8 * 60)) * 100, 2
                ) if total_call_duration_minutes > 0 else 0.0

                overall_average_call_duration_minutes = round(
                    total_call_duration_minutes / overall_total_bill, 2
                ) if overall_total_bill > 0 else 0.0

                response_data.append({
                    "created_date": created_date,
                    "bdo_present_count": bdo_present_count,
                    "bdo_absent_count": bdo_absent_count,
                    "bdo_half_day_count": bdo_half_day_count,
                    "total_bill": overall_total_bill,
                    "total_volume": round(overall_total_volume, 2),
                    "total_call_duration": format_seconds_to_hhmmss(
                        overall_total_call_duration_seconds
                    ),
                    "call_duration_average": overall_call_duration_average,
                    "average_call_duration_minutes": overall_average_call_duration_minutes,
                    "family_data": family_data
                })

            response_data = sorted(
                response_data,
                key=lambda x: x["created_date"],
                reverse=True
            )

            paginator = StandardPagination()
            paginated_data = paginator.paginate_queryset(response_data, request)
            serializer = BdmDateWiseOverallSerializer(paginated_data, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "BDM overall report fetched successfully",
                "count": len(response_data),
                "data": serializer.data
            })

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching BDM overall report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BdmDailyOverallReportView(BaseTokenView):

    def get(self, request):
        try:
            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")
            bdm_id = request.GET.get("bdm")

            analysis_queryset = BDMOrderAnalysisData.objects.all()

            if start_date:
                try:
                    start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
                    analysis_queryset = analysis_queryset.filter(attendance_date__gte=start_date_obj)
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if end_date:
                try:
                    end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
                    analysis_queryset = analysis_queryset.filter(attendance_date__lte=end_date_obj)
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            bdm_user = None
            if bdm_id:
                try:
                    bdm_id = int(bdm_id)
                    bdm_user = User.objects.filter(id=bdm_id).first()
                    if not bdm_user:
                        return Response(
                            {
                                "status": "error",
                                "message": "Invalid bdm id"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except ValueError:
                    return Response(
                        {
                            "status": "error",
                            "message": "bdm must be a valid integer id"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            analysis_dates = analysis_queryset.values_list(
                "attendance_date", flat=True
            ).distinct().order_by("-attendance_date")

            if not analysis_dates:
                return Response(
                    {
                        "status": "success",
                        "message": "No BDM data found",
                        "count": 0,
                        "data": []
                    },
                    status=status.HTTP_200_OK
                )

            response_data = []

            for created_date in analysis_dates:
                attendance_qs = BDMOrderAnalysisStaff.objects.filter(
                    analysis__attendance_date=created_date
                )

                if bdm_id:
                    attendance_qs = attendance_qs.filter(staff_id=bdm_id)

                bdo_present_count = attendance_qs.filter(status='present').count()
                bdo_absent_count = attendance_qs.filter(status='absent').count()
                bdo_half_day_count = attendance_qs.filter(status='half_day').count()

                bdm_map = {}

                # --------------------------------------------------
                # 1) BUILD BDM MAP FROM ORDER SELECTIONS
                # --------------------------------------------------
                selections = BdmOrderSelection.objects.filter(
                    created_at__date=created_date
                ).select_related('bdm', 'bdm__family').order_by('-created_at')

                if bdm_id:
                    selections = selections.filter(bdm_id=bdm_id)

                for selection in selections:
                    bdm = selection.bdm
                    if not bdm:
                        continue

                    current_bdm_id = bdm.id
                    family = getattr(bdm, 'family', None)

                    if current_bdm_id not in bdm_map:
                        bdm_map[current_bdm_id] = {
                            "bdm_id": bdm.id,
                            "bdm_name": getattr(bdm, "name", str(bdm)),
                            "family_id": family.id if family else None,
                            "family_name": family.name if family else "No Family",
                            "selection_ids": [],
                            "total_bill": 0,
                            "total_order_count": 0,
                            "total_volume": 0.0,
                            "total_call_duration_seconds": 0,
                        }

                    bdm_map[current_bdm_id]["selection_ids"].append(selection.id)

                for current_bdm_id, bdm_row in bdm_map.items():
                    selection_ids = bdm_row["selection_ids"]

                    items = BdmOrderSelectionItem.objects.filter(
                        selection_id__in=selection_ids
                    ).select_related('order')

                    bdm_row["total_bill"] = items.count()
                    bdm_row["total_order_count"] = items.count()

                    total_volume = Decimal("0.0")
                    for item in items:
                        if item.order and item.order.total_amount:
                            total_volume += Decimal(str(item.order.total_amount))

                    bdm_row["total_volume"] = float(total_volume)

                # --------------------------------------------------
                # 2) ALSO INCLUDE ALL BDMs FROM SALES ANALYSIS
                # --------------------------------------------------
                sales_entries = SalesAnalysis.objects.filter(
                    created_at__date=created_date
                ).exclude(status='dsr rejected').select_related(
                    'created_by',
                    'created_by__family'
                )

                if bdm_id:
                    sales_entries = sales_entries.filter(created_by_id=bdm_id)

                for sale in sales_entries:
                    if not sale.created_by:
                        continue

                    current_bdm_id = sale.created_by.id
                    bdm = sale.created_by
                    family = getattr(bdm, 'family', None)

                    if current_bdm_id not in bdm_map:
                        bdm_map[current_bdm_id] = {
                            "bdm_id": bdm.id,
                            "bdm_name": getattr(bdm, "name", str(bdm)),
                            "family_id": family.id if family else None,
                            "family_name": family.name if family else "No Family",
                            "selection_ids": [],
                            "total_bill": 0,
                            "total_order_count": 0,
                            "total_volume": 0.0,
                            "total_call_duration_seconds": 0,
                        }

                    if sale.call_duration:
                        bdm_map[current_bdm_id]["total_call_duration_seconds"] += parse_duration_to_seconds(
                            sale.call_duration
                        )

                family_map = {}

                for _, bdm_row in bdm_map.items():
                    family_id = bdm_row["family_id"]
                    family_name = bdm_row["family_name"]

                    if family_id not in family_map:
                        family_map[family_id] = {
                            "family_id": family_id,
                            "family_name": family_name,
                            "bdm_count": 0,
                            "total_bill": 0,
                            "total_order_count": 0,
                            "total_volume": 0.0,
                            "total_call_duration_seconds": 0,
                            "bdm_data": []
                        }

                    bdm_call_duration_minutes = bdm_row["total_call_duration_seconds"] / 60
                    bdm_call_duration_average = round(
                        (bdm_call_duration_minutes / (8 * 60)) * 100, 2
                    ) if bdm_call_duration_minutes > 0 else 0.0

                    bdm_average_call_duration_minutes = round(
                        bdm_call_duration_minutes / bdm_row["total_bill"], 2
                    ) if bdm_row["total_bill"] > 0 else 0.0

                    family_map[family_id]["bdm_count"] += 1
                    family_map[family_id]["total_bill"] += bdm_row["total_bill"]
                    family_map[family_id]["total_order_count"] += bdm_row["total_order_count"]
                    family_map[family_id]["total_volume"] += bdm_row["total_volume"]
                    family_map[family_id]["total_call_duration_seconds"] += bdm_row["total_call_duration_seconds"]

                    family_map[family_id]["bdm_data"].append({
                        "bdm_id": bdm_row["bdm_id"],
                        "bdm_name": bdm_row["bdm_name"],
                        "total_bill": bdm_row["total_bill"],
                        "total_order_count": bdm_row["total_order_count"],
                        "total_volume": round(bdm_row["total_volume"], 2),
                        "total_call_duration": format_seconds_to_hhmmss(
                            bdm_row["total_call_duration_seconds"]
                        ),
                        "call_duration_average": bdm_call_duration_average,
                        "average_call_duration_minutes": bdm_average_call_duration_minutes,
                    })

                family_data = []
                overall_total_bill = 0
                overall_total_volume = 0.0
                overall_total_call_duration_seconds = 0

                for _, family_row in family_map.items():
                    family_row["bdm_data"] = sorted(
                        family_row["bdm_data"],
                        key=lambda x: x["bdm_id"],
                        reverse=True
                    )

                    family_call_duration_minutes = family_row["total_call_duration_seconds"] / 60
                    family_call_duration_average = round(
                        (family_call_duration_minutes / (8 * 60)) * 100, 2
                    ) if family_call_duration_minutes > 0 else 0.0

                    family_average_call_duration_minutes = round(
                        family_call_duration_minutes / family_row["total_bill"], 2
                    ) if family_row["total_bill"] > 0 else 0.0

                    family_data.append({
                        "family_id": family_row["family_id"],
                        "family_name": family_row["family_name"],
                        "bdm_count": family_row["bdm_count"],
                        "total_bill": family_row["total_bill"],
                        "total_order_count": family_row["total_order_count"],
                        "total_volume": round(family_row["total_volume"], 2),
                        "total_call_duration": format_seconds_to_hhmmss(
                            family_row["total_call_duration_seconds"]
                        ),
                        "call_duration_average": family_call_duration_average,
                        "average_call_duration_minutes": family_average_call_duration_minutes,
                        "bdm_data": family_row["bdm_data"]
                    })

                    overall_total_bill += family_row["total_bill"]
                    overall_total_volume += family_row["total_volume"]
                    overall_total_call_duration_seconds += family_row["total_call_duration_seconds"]

                family_data = sorted(
                    family_data,
                    key=lambda x: (x["family_name"] or "").lower()
                )

                total_call_duration_minutes = overall_total_call_duration_seconds / 60
                overall_call_duration_average = round(
                    (total_call_duration_minutes / (8 * 60)) * 100, 2
                ) if total_call_duration_minutes > 0 else 0.0

                overall_average_call_duration_minutes = round(
                    total_call_duration_minutes / overall_total_bill, 2
                ) if overall_total_bill > 0 else 0.0

                response_data.append({
                    "created_date": created_date,
                    "bdo_present_count": bdo_present_count,
                    "bdo_absent_count": bdo_absent_count,
                    "bdo_half_day_count": bdo_half_day_count,
                    "total_bill": overall_total_bill,
                    "total_volume": round(overall_total_volume, 2),
                    "total_call_duration": format_seconds_to_hhmmss(
                        overall_total_call_duration_seconds
                    ),
                    "call_duration_average": overall_call_duration_average,
                    "average_call_duration_minutes": overall_average_call_duration_minutes,
                    "family_data": family_data
                })

            response_data = sorted(
                response_data,
                key=lambda x: x["created_date"],
                reverse=True
            )

            paginator = StandardPagination()
            paginated_data = paginator.paginate_queryset(response_data, request)
            serializer = BdmDateWiseOverallSerializer(paginated_data, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "BDM overall family-wise report fetched successfully",
                "count": len(response_data),
                "data": serializer.data
            })

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching BDM overall family-wise report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Product Buying from another company/industries - Seller Details


class CurrencyListCreateView(BaseTokenView):

    def get(self, request):

        user, error = self.get_user_from_token(request)
        if error:
            return error
        
        try:
            currencies = Currency.objects.all().order_by("-id")
            serializer = CurrencySerializer(currencies, many=True)

            return Response({
                "success": True,
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
    def post(self, request):

        user, error = self.get_user_from_token(request)
        if error:
            return error
        
        try:
            serializer = CurrencySerializer(data=request.data)

            if serializer.is_valid():
                serializer.save(created_by=user)

                return Response({
                    "success": True,
                    "message": "Currency created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "success": False,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CurrencyDetailView(BaseTokenView):

    def get(self, request, currency_id):

        user, error = self.get_user_from_token(request)
        if error:
            return error
        
        try:
            currency = Currency.objects.get(id=currency_id)
            serializer = CurrencySerializer(currency)

            return Response({
                "success": True,
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Currency.DoesNotExist:
            return Response({
                "success": False,
                "message": "Currency not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    
    def put(self, request, currency_id):

        user, error = self.get_user_from_token(request)
        if error:
            return error
        
        try:
            currency = Currency.objects.get(id=currency_id)

            serializer = CurrencySerializer(currency, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()

                return Response({
                    "success": True,
                    "message": "Currency updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Currency.DoesNotExist:
            return Response({
                "success": False,
                "message": "Currency not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "message": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductSellerDetailsView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            queryset = ProductSellerDetails.objects.all().order_by("-id")
            serializer = ProductSellerDetailsViewSerializer(queryset, many=True)

            return Response({
                "status": "success",
                "message": "Seller details fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except DatabaseError:
            return Response({
                "status": "error",
                "message": "Database error occurred"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = ProductSellerDetailsSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(created_by=user)

                return Response({
                    "status": "success",
                    "message": "Seller details created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "status": "error",
                "message": "Validation failed",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except DatabaseError:
            return Response({
                "status": "error",
                "message": "Database error occurred"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductSellerDetailsByIdView(BaseTokenView):

    def get(self, request, id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            seller = ProductSellerDetails.objects.get(id=id)
            serializer = ProductSellerDetailsViewSerializer(seller)

            return Response({
                "status": "success",
                "message": "Seller details fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except ProductSellerDetails.DoesNotExist:
            return Response({
                "status": "error",
                "message": "Seller not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except DatabaseError:
            return Response({
                "status": "error",
                "message": "Database error occurred"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            seller = ProductSellerDetails.objects.get(id=id)

            serializer = ProductSellerDetailsSerializer(
                seller,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                serializer.save()   # created_by not changing in update

                return Response({
                    "status": "success",
                    "message": "Seller details updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "status": "error",
                "message": "Validation failed",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except ProductSellerDetails.DoesNotExist:
            return Response({
                "status": "error",
                "message": "Seller not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except DatabaseError:
            return Response({
                "status": "error",
                "message": "Database error occurred"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "An unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CreateProductSellerInvoice(BaseTokenView):

    @transaction.atomic
    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            seller_id = request.data.get("seller_id")
            note = request.data.get("note")
            invoice_date = request.data.get("invoice_date")
            company_id = request.data.get("company")
            currency_id = request.data.get("currency")
            currency_rate = request.data.get("currency_rate")

            if not seller_id:
                return Response({"status": "error", "message": "seller_id is required"}, status=400)
            
            if not company_id:
                return Response({"status": "error", "message": "company is required"}, status=400)

            if not invoice_date:
                return Response({"status": "error", "message": "invoice_date is required"}, status=400)
            
            currency = None
            if currency_id:
                currency = get_object_or_404(Currency, id=currency_id)

            parsed_date = parse_date(invoice_date)

            if not parsed_date:
                return Response({"status": "error", "message": "Invalid invoice_date format. Use YYYY-MM-DD"}, status=400)

            seller = get_object_or_404(ProductSellerDetails, id=seller_id)

            company = get_object_or_404(Company, id=company_id)

            cart_items = ProductSellerCartDetails.objects.filter(user=user)

            if not cart_items.exists():
                return Response({"status": "error", "message": "Cart is empty"}, status=400)

            invoice = ProductSellerInvoice.objects.create(
                created_by=user,
                seller=seller,
                note=note,
                invoice_date=parsed_date,
                company=company,
                currency=currency,
                currency_rate=currency_rate
            )

            total_amount = 0

            for cart in cart_items:
                product = cart.product
                qty = int(cart.quantity)
                price = float(cart.price or product.purchase_rate or 0)
                discount = float(cart.discount or 0)
                tax = float(product.tax or 0)

                line_total = (qty * price) - discount
                total_amount += line_total

                ProductSellerInvoiceItem.objects.create(
                    invoice=invoice,
                    product=product,
                    quantity=qty,
                    price=price,
                    discount=discount,
                    tax=tax,
                    total=line_total
                )

               
            invoice.total_amount = total_amount
            invoice.save()

            cart_items.delete()

            return Response({
                "status": "success",
                "message": "Purchase invoice created successfully",
                "data": ProductSellerInvoiceSerializer(invoice).data
            }, status=201)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)


class ProductSellerInvoiceListView(BaseTokenView):

    def get(self, request):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        invoices = ProductSellerInvoice.objects.all().order_by("-id")
        serializer = ProductSellerInvoiceListSerializer(invoices, many=True)

        return Response({
            "status": "success",
            "data": serializer.data
        }, status=200)



class ProductSellerCartView(BaseTokenView):

    def get(self, request):
        user, error_response = self.get_user_from_token(request)
        if error_response:
            return error_response

        cart = ProductSellerCartDetails.objects.filter(user=user).order_by("-id")

        data = []
        for item in cart:
            product = item.product

            image_url = None
            if product.image:
                image_url = request.build_absolute_uri(product.image.url)

            data.append({
                "id": item.id,
                "product_id": item.product.id,
                "product_name": item.product.name,
                "quantity": item.quantity,
                "price": item.price,
                "discount": item.discount,
                "note": item.note,
                "image": image_url
            })

        return Response({"status": "success", "data": data})


    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            product_id = request.data.get("product_id")
            quantity = request.data.get("quantity", 1)
            discount = request.data.get("discount", 0)

            if not product_id:
                return Response({
                    "status": "error",
                    "message": "product_id is required"
                }, status=400)

            product = get_object_or_404(Products, id=product_id)

            # Take price from Product model
            price = product.purchase_rate  # or product.selling_price

            cart_item, created = ProductSellerCartDetails.objects.get_or_create(
                user=user,
                product=product,
                defaults={
                    "quantity": quantity,
                    "discount": discount,
                    "price": price
                }
            )

            if not created:
                cart_item.quantity = int(quantity)
                cart_item.discount = discount
                cart_item.price = price
                cart_item.save()

            return Response({
                "status": "success",
                "message": "Product added to seller cart successfully"
            }, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)



class ProductSellerInvoiceDetailView(BaseTokenView):

    def get(self, request, invoice_id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            invoice = get_object_or_404(ProductSellerInvoice, id=invoice_id)

            items = ProductSellerInvoiceItem.objects.filter(invoice=invoice)

            items_data = []
            for item in items:
                product = item.product

                image_url = None
                if product.image:
                    image_url = request.build_absolute_uri(product.image.url)

                items_data.append({
                    "id": item.id,
                    "product_id": product.id,
                    "product_name": product.name,
                    "quantity": item.quantity,
                    "price": item.price,
                    "discount": item.discount,
                    "tax": item.tax,
                    "total": item.total,
                    "image": image_url
                })

            data = {
                "invoice_id": invoice.id,
                "invoice_no": invoice.invoice_no,
                "invoice_date": invoice.invoice_date,
                "total_amount": invoice.total_amount,
                "note": invoice.note,

                # Seller Details
                "seller_id": invoice.seller.id,
                "seller_name": invoice.seller.name,
                "company_name": invoice.company.name if invoice.company else None,
                "gstin": invoice.seller.gstin,
                "phone": invoice.seller.phone,
                "email": invoice.seller.email,
                "address": invoice.seller.address,

                "currency": invoice.currency.id if invoice.currency else None,
                "currency_name": invoice.currency.currency if invoice.currency else None,
                "currency_rate": invoice.currency_rate,

                # Items
                "items": items_data
            }

            return Response({"status": "success", "data": data}, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)


    @transaction.atomic
    def put(self, request, invoice_id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            invoice = get_object_or_404(ProductSellerInvoice, id=invoice_id)

            note = request.data.get("note", None)
            invoice_date = request.data.get("invoice_date", None)
            company_id = request.data.get("company_id", None)
            seller_id = request.data.get("seller_id", None)
            currency_id = request.data.get("currency", None)
            currency_rate = request.data.get("currency_rate", None)

            # items key should be checked properly
            items = request.data.get("items", None)

            updated = False

            # update note only if provided
            if note is not None:
                invoice.note = note
                updated = True

            # update invoice_date only if provided
            if invoice_date is not None:
                parsed_date = parse_date(invoice_date)
                if not parsed_date:
                    return Response({
                        "status": "error",
                        "message": "Invalid invoice_date format. Use YYYY-MM-DD"
                    }, status=400)

                invoice.invoice_date = parsed_date
                updated = True

            # update company only if provided
            if company_id is not None:
                company = get_object_or_404(Company, id=company_id)
                invoice.company = company
                updated = True

            # update seller only if provided
            if seller_id is not None:
                seller = get_object_or_404(ProductSellerDetails, id=seller_id)
                invoice.seller = seller
                updated = True

            # update currency only if provided
            if currency_id is not None:
                currency = get_object_or_404(Currency, id=currency_id)
                invoice.currency = currency
                updated = True

            if currency_rate is not None:
                invoice.currency_rate = currency_rate
                updated = True

            # update items only if items is sent
            if items is not None:
                total_amount = 0

                for item in items:
                    item_id = item.get("id")

                    if not item_id:
                        continue

                    invoice_item = get_object_or_404(
                        ProductSellerInvoiceItem,
                        id=item_id,
                        invoice=invoice
                    )

                    if "quantity" in item:
                        invoice_item.quantity = item["quantity"]

                    if "price" in item:
                        invoice_item.price = item["price"]

                    if "discount" in item:
                        invoice_item.discount = item["discount"]

                    if "tax" in item:
                        invoice_item.tax = item["tax"]

                    invoice_item.total = (invoice_item.quantity * invoice_item.price) - invoice_item.discount
                    invoice_item.save()

                # recalculate total from DB after update
                all_items = ProductSellerInvoiceItem.objects.filter(invoice=invoice)
                for it in all_items:
                    total_amount += float(it.total)

                invoice.total_amount = total_amount
                updated = True

            if updated:
                invoice.save()

            return Response({
                "status": "success",
                "message": "Invoice updated successfully"
            }, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)
            


class ProductSellerCartUpdateView(BaseTokenView):

    def put(self, request, id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cart_item = get_object_or_404(ProductSellerCartDetails, id=id, user=user)

            quantity = request.data.get("quantity")
            discount = request.data.get("discount")
            price = request.data.get("price")
            note = request.data.get("note")

            if quantity is not None:
                cart_item.quantity = int(quantity)

            if discount is not None:
                cart_item.discount = discount

            if price is not None:
                cart_item.price = price

            if note is not None:
                cart_item.note = note

            cart_item.save()

            return Response({
                "status": "success",
                "message": "Cart item updated successfully"
            }, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)



class ProductSellerCartDeleteView(BaseTokenView):

    def delete(self, request, id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cart_item = get_object_or_404(ProductSellerCartDetails, id=id, user=user)
            cart_item.delete()

            return Response({
                "status": "success",
                "message": "Product removed from cart successfully"
            }, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)




class PrintSellerInvoiceView(BaseTokenView):

    def get(self, request, invoice_id):
        try:

            invoice = get_object_or_404(ProductSellerInvoice, id=invoice_id)

            items = ProductSellerInvoiceItem.objects.filter(invoice=invoice)

            return render(request, "seller_invoice.html", {
                "invoice": invoice,
                "items": items
            })

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)


class ProductSellerInvoiceItemDeleteView(BaseTokenView):

    def delete(self, request, item_id):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Get item
            invoice_item = get_object_or_404(
                ProductSellerInvoiceItem,
                id=item_id
            )

            invoice = invoice_item.invoice

            # Delete item
            invoice_item.delete()

            # Recalculate total
            from django.db.models import Sum

            total_amount = ProductSellerInvoiceItem.objects.filter(
                invoice=invoice
            ).aggregate(total=Sum("total"))["total"] or 0

            invoice.total_amount = total_amount
            invoice.save()

            return Response({
                "status": "success",
                "message": "Item deleted successfully"
            }, status=200)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)


class ProductSellerInvoiceItemAddView(BaseTokenView):

    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            invoice_id = request.data.get("invoice_id")
            product_id = request.data.get("product_id")
            quantity = int(request.data.get("quantity", 1))
            price = float(request.data.get("price", 0))
            discount = float(request.data.get("discount", 0))
            tax = float(request.data.get("tax", 0))

            if not invoice_id or not product_id:
                return Response({
                    "status": "error",
                    "message": "invoice_id and product_id are required"
                }, status=400)

            invoice = get_object_or_404(ProductSellerInvoice, id=invoice_id)
            product = get_object_or_404(Products, id=product_id)

            # calculate total
            total = (quantity * price) - discount

            # create item
            ProductSellerInvoiceItem.objects.create(
                invoice=invoice,
                product=product,
                quantity=quantity,
                price=price,
                discount=discount,
                tax=tax,
                total=total
            )

            # recalc total
            from django.db.models import Sum

            total_amount = ProductSellerInvoiceItem.objects.filter(
                invoice=invoice
            ).aggregate(total=Sum("total"))["total"] or 0

            invoice.total_amount = total_amount
            invoice.save()

            return Response({
                "status": "success",
                "message": "Product added to invoice successfully"
            }, status=201)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "errors": str(e)
            }, status=500)


class MyDailySalesReportView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            
            month = request.GET.get("month")
            year = request.GET.get("year")
            state_id = request.GET.get("state_id")

            if not month or not year or not state_id:
                return Response({
                    "status": "error",
                    "message": "month, year and state_id are required"
                }, status=400)

            month = int(month)
            year = int(year)
            state_id = int(state_id)

            # Validate month
            if month < 1 or month > 12:
                return Response({
                    "status": "error",
                    "message": "month must be between 1 and 12"
                }, status=400)

            state = State.objects.get(id=state_id)

            days_in_month = calendar.monthrange(year, month)[1]
            dates = list(range(1, days_in_month + 1))

            reports = DailySalesReport.objects.filter(
                user=user,
                state_id=state_id,
                created_at__year=year,
                created_at__month=month
            )

            district_list = Districts.objects.filter(state_id=state_id).order_by("name")

            final_data = []
            column_totals = {str(day): 0 for day in dates}
            grand_total = 0

            for dist in district_list:
                daily_counts = {str(day): 0 for day in dates}
                row_total = 0

                dist_reports = reports.filter(district=dist)

                for day in dates:
                    invoice_count = dist_reports.filter(created_at__day=day).count()
                    daily_counts[str(day)] = invoice_count

                    row_total += invoice_count
                    column_totals[str(day)] += invoice_count

                grand_total += row_total

                final_data.append({
                    "district": dist.name,
                    "daily_counts": daily_counts,
                    "total": row_total
                })

            month_name = datetime(year, month, 1).strftime("%B %Y")


            # state summary calculations
            total_invoices = grand_total
            average_per_day = round(total_invoices / days_in_month, 2) if days_in_month > 0 else 0

            highest_day = None
            highest_day_count = 0

            lowest_day = None
            lowest_day_count = None

            if column_totals:
                highest_day = max(column_totals, key=lambda k: column_totals[k])
                highest_day_count = column_totals[highest_day]

                lowest_day = min(column_totals, key=lambda k: column_totals[k])
                lowest_day_count = column_totals[lowest_day]

            state_summary = {
                "total_invoices": total_invoices,
                "average_per_day": average_per_day,
                "highest_day": int(highest_day) if highest_day else None,
                "highest_day_count": highest_day_count,
                "lowest_day": int(lowest_day) if lowest_day else None,
                "lowest_day_count": lowest_day_count
            }

            return Response({
                "status": "success",
                "user": user.name,
                "state": state.name,
                "month": month_name,
                "dates": dates,
                "districts": final_data,
                "column_totals": column_totals,
                "grand_total": grand_total,
                "state_summary": state_summary
            })

        except State.DoesNotExist:
            return Response({
                "status": "error",
                "message": "State not found"
            }, status=404)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "error": str(e)
            }, status=500)



class AllUsersDailySalesReportView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            month = request.GET.get("month")
            year = request.GET.get("year")
            state_id = request.GET.get("state_id")
            user_id = request.GET.get("user_id")

            if not month or not year:
                return Response({
                    "status": "error",
                    "message": "month and year are required"
                }, status=400)

            month = int(month)
            year = int(year)

            if month < 1 or month > 12:
                return Response({
                    "status": "error",
                    "message": "month must be between 1 and 12"
                }, status=400)

            if state_id:
                state_id = int(state_id)

            if user_id:
                user_id = int(user_id)

            days_in_month = calendar.monthrange(year, month)[1]
            dates = list(range(1, days_in_month + 1))

            month_name = datetime(year, month, 1).strftime("%B %Y")

            reports = DailySalesReport.objects.filter(
                created_at__year=year,
                created_at__month=month
            )

            if user_id:
                reports = reports.filter(user_id=user_id)

            if state_id:
                state = State.objects.get(id=state_id)

                reports = reports.filter(state_id=state_id)

                district_list = Districts.objects.filter(
                    state_id=state_id
                ).order_by("name")

            else:
                # if no state_id then use allocated_states of the selected user_id
                if not user_id:
                    return Response({
                        "status": "error",
                        "message": "user_id is required when state_id is not given"
                    }, status=400)

                user_obj = User.objects.get(id=user_id)
                allocated_states = user_obj.allocated_states.all()

                reports = reports.filter(state__in=allocated_states)

                district_list = Districts.objects.filter(
                    state__in=allocated_states
                ).order_by("state__name", "name")

                state = None

            users = reports.values_list("user_id", flat=True).distinct()

            final_users_data = []

            for uid in users:
                user_obj = User.objects.get(id=uid)

                column_totals = {str(day): 0 for day in dates}
                grand_total = 0

                user_reports = reports.filter(user_id=uid)

                statewise_data = {}

                for dist in district_list:
                    state_name = dist.state.name if dist.state else ""

                    if state_name not in statewise_data:
                        statewise_data[state_name] = []

                    daily_counts = {str(day): 0 for day in dates}
                    row_total = 0

                    dist_reports = user_reports.filter(district=dist)

                    for day in dates:
                        invoice_count = dist_reports.filter(created_at__day=day).count()
                        daily_counts[str(day)] = invoice_count

                        row_total += invoice_count
                        column_totals[str(day)] += invoice_count

                    grand_total += row_total

                    statewise_data[state_name].append({
                        "district": dist.name,
                        "daily_counts": daily_counts,
                        "total": row_total
                    })

                user_data = []

                for sname, dlist in statewise_data.items():
                    user_data.append({
                        "state": sname,
                        "districts": dlist
                    })


                # state summary calculations for each user
                state_summaries = []

                for sname, dlist in statewise_data.items():

                    state_total_invoices = 0
                    state_column_totals = {str(day): 0 for day in dates}

                    # calculate totals from districts list
                    for dist_item in dlist:
                        state_total_invoices += dist_item["total"]

                        for day in dates:
                            state_column_totals[str(day)] += dist_item["daily_counts"][str(day)]

                    state_average_per_day = round(state_total_invoices / days_in_month, 2) if days_in_month > 0 else 0

                    state_highest_day = None
                    state_highest_day_count = 0

                    state_lowest_day = None
                    state_lowest_day_count = None

                    if state_column_totals:
                        state_highest_day = max(state_column_totals, key=lambda k: state_column_totals[k])
                        state_highest_day_count = state_column_totals[state_highest_day]

                        state_lowest_day = min(state_column_totals, key=lambda k: state_column_totals[k])
                        state_lowest_day_count = state_column_totals[state_lowest_day]

                    state_summaries.append({
                        "state": sname,
                        "total_invoices": state_total_invoices,
                        "average_per_day": state_average_per_day,
                        "highest_day": int(state_highest_day) if state_highest_day else None,
                        "highest_day_count": state_highest_day_count,
                        "lowest_day": int(state_lowest_day) if state_lowest_day else None,
                        "lowest_day_count": state_lowest_day_count
                    })

                final_users_data.append({
                    "user_id": user_obj.id,
                    "user_name": user_obj.name,
                    "districts": user_data,
                    "column_totals": column_totals,
                    "grand_total": grand_total,
                    "state_summary": state_summaries
                })

            return Response({
                "status": "success",
                "state": state.name if state else "",
                "month": month_name,
                "dates": dates,
                "users": final_users_data
            })

        except State.DoesNotExist:
            return Response({
                "status": "error",
                "message": "State not found"
            }, status=404)

        except User.DoesNotExist:
            return Response({
                "status": "error",
                "message": "User not found"
            }, status=404)

        except Exception as e:
            return Response({
                "status": "error",
                "message": "Something went wrong",
                "error": str(e)
            }, status=500)




class LoggedUserMonthlyCategoryReportView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            month = request.GET.get("month")
            year = request.GET.get("year")

            if not month or not year:
                return JsonResponse({
                    "status": "error",
                    "message": "month and year are required"
                }, status=400)

            month = int(month)
            year = int(year)

            start_date = datetime(year, month, 1)
            last_day = calendar.monthrange(year, month)[1]
            end_date = datetime(year, month, last_day, 23, 59, 59)

            # Get all categories (for fixed columns)
            categories = list(
                ProductCategoryModel.objects.values_list("category_name", flat=True)
            )

            # Fetch report data
            report_qs = (
                OrderItem.objects
                .filter(
                    order__daily_sales_reports__user=user,
                    order__daily_sales_reports__created_at__range=[start_date, end_date]
                )
                .values(
                    "order__daily_sales_reports__state__name",
                    "order__daily_sales_reports__district__name",
                    "product__product_category__category_name",
                )
                .annotate(total_qty=Sum("quantity"))
            )

            output = {}
            category_totals = {cat: 0 for cat in categories}
            category_totals["Others"] = 0
            grand_total = 0

            for row in report_qs:
                state = row["order__daily_sales_reports__state__name"]
                district = row["order__daily_sales_reports__district__name"]
                category = row["product__product_category__category_name"] or "Others"
                qty = row["total_qty"] or 0

                if state not in output:
                    output[state] = {}

                if district not in output[state]:
                    output[state][district] = {cat: 0 for cat in categories}
                    output[state][district]["Others"] = 0
                    output[state][district]["total"] = 0

                if category not in output[state][district]:
                    category = "Others"

                output[state][district][category] += qty
                output[state][district]["total"] += qty

                if category not in category_totals:
                    category_totals["Others"] += qty
                else:
                    category_totals[category] += qty

                grand_total += qty

            category_totals["total"] = grand_total


            # state summary calculations
            state_summary_qs = (
                OrderItem.objects
                .filter(
                    order__daily_sales_reports__user=user,
                    order__daily_sales_reports__created_at__range=[start_date, end_date]
                )
                .values("order__daily_sales_reports__state__name")
                .annotate(total_qty=Sum("quantity"))
                .order_by("order__daily_sales_reports__state__name")
            )

            state_summary = []

            for row in state_summary_qs:
                state_summary.append({
                    "state": row["order__daily_sales_reports__state__name"],
                    "total_quantity": row["total_qty"] or 0
                })

            return JsonResponse({
                "status": "success",
                "user": user.name,
                "month": month,
                "year": year,
                "categories": categories + ["Others"],
                "data": output,
                "category_totals": category_totals,
                "state_summary": state_summary
            }, status=200)

        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": "Something went wrong",
                "error": str(e)
            }, status=500)




class AllUsersMonthlyCategoryReportView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            month = request.GET.get("month")
            year = request.GET.get("year")

            if not month or not year:
                return JsonResponse({
                    "status": "error",
                    "message": "month and year are required"
                }, status=400)

            month = int(month)
            year = int(year)

            start_date = datetime(year, month, 1)
            last_day = calendar.monthrange(year, month)[1]
            end_date = datetime(year, month, last_day, 23, 59, 59)

            categories = list(
                ProductCategoryModel.objects.values_list("category_name", flat=True)
            )

            report_qs = (
                OrderItem.objects
                .filter(order__daily_sales_reports__created_at__range=[start_date, end_date])
                .values(
                    "order__daily_sales_reports__user__name",
                    "order__daily_sales_reports__state__name",
                    "order__daily_sales_reports__district__name",
                    "product__product_category__category_name",
                )
                .annotate(total_qty=Sum("quantity"))
                .order_by(
                    "order__daily_sales_reports__user__name",
                    "order__daily_sales_reports__state__name",
                    "order__daily_sales_reports__district__name",
                )
            )

            final_output = {}

            for row in report_qs:
                uname = row["order__daily_sales_reports__user__name"]
                state = row["order__daily_sales_reports__state__name"]
                district = row["order__daily_sales_reports__district__name"]
                category = row["product__product_category__category_name"] or "Others"
                qty = row["total_qty"] or 0

                if uname not in final_output:
                    final_output[uname] = {}

                if state not in final_output[uname]:
                    final_output[uname][state] = {}

                if district not in final_output[uname][state]:
                    final_output[uname][state][district] = {cat: 0 for cat in categories}
                    final_output[uname][state][district]["Others"] = 0
                    final_output[uname][state][district]["total"] = 0

                if category not in final_output[uname][state][district]:
                    category = "Others"

                final_output[uname][state][district][category] += qty
                final_output[uname][state][district]["total"] += qty


            # state summary calculations
            state_summary_qs = (
                OrderItem.objects
                .filter(order__daily_sales_reports__created_at__range=[start_date, end_date])
                .values(
                    "order__daily_sales_reports__user__name",
                    "order__daily_sales_reports__state__name"
                )
                .annotate(total_qty=Sum("quantity"))
                .order_by(
                    "order__daily_sales_reports__user__name",
                    "order__daily_sales_reports__state__name"
                )
            )

            state_summary_output = {}

            for row in state_summary_qs:
                uname = row["order__daily_sales_reports__user__name"]
                state = row["order__daily_sales_reports__state__name"]
                qty = row["total_qty"] or 0

                if uname not in state_summary_output:
                    state_summary_output[uname] = []

                state_summary_output[uname].append({
                    "state": state,
                    "total_quantity": qty
                })

            return JsonResponse({
                "status": "success",
                "month": month,
                "year": year,
                "categories": categories + ["Others"],
                "data": final_output,
                "state_summary": state_summary_output
            }, status=200)

        except Exception as e:
            return JsonResponse({
                "status": "error",
                "message": "Something went wrong",
                "error": str(e)
            }, status=500)


class FamilyStateBDOReport(APIView):

    def get(self, request):

        try:
            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")

            orders = Order.objects.exclude(
                status="Invoice Rejected"
            ).exclude(
                family__name__iexact="bepocart"
            )

            # Date filter
            if start_date and end_date:
                orders = orders.filter(
                    order_date__range=[start_date, end_date]
                )

            orders = (
                orders
                .values(
                    "family__name",
                    "state__name",
                    "manage_staff__name"
                )
                .annotate(
                    bills=Count("id"),
                    amount=Sum("total_amount")
                )
                .order_by("family__name", "state__name", "manage_staff__name")
            )

            report = defaultdict(lambda: {
                "states": defaultdict(lambda: {
                    "bdo": [],
                    "state_total": 0
                }),
                "family_total": 0,
                "family_bill_total": 0
            })

            grand_total = 0
            total_bills = 0

            for row in orders:

                family = row["family__name"]
                state = row["state__name"]
                staff = row["manage_staff__name"]
                bills = row["bills"]
                amount = row["amount"] or 0

                report[family]["states"][state]["bdo"].append({
                    "name": staff,
                    "bills": bills,
                    "amount": amount
                })

                report[family]["states"][state]["state_total"] += amount
                report[family]["family_total"] += amount
                report[family]["family_bill_total"] += bills

                grand_total += amount
                total_bills += bills

            data = []

            for family, fdata in report.items():

                states_list = []

                for state, sdata in fdata["states"].items():
                    states_list.append({
                        "state": state,
                        "bdo_details": sdata["bdo"],
                        "state_total": sdata["state_total"]
                    })

                data.append({
                    "family": family,
                    "states": states_list,
                    "family_total": fdata["family_total"],
                    "family_bill_total": fdata["family_bill_total"]
                })

            return Response({
                "status": "success",
                "data": data,
                "total_bills": total_bills,
                "grand_total": grand_total
            })

        except Exception as e:
            return Response({
                "status": "error",
                "message": str(e)
            }, status=500)



class EmployeeExitCreateListView(BaseTokenView):
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            data = request.data.copy()
            data["created_by"] = authUser.pk

            serializer = EmplyeeExitAddSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Employee exit created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while creating employee exit",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            exit_date_from = request.GET.get("exit_date_from", "").strip()
            exit_date_to = request.GET.get("exit_date_to", "").strip()
            employee_department = request.GET.get("employee_department", "").strip()

            exits = EmployeeExit.objects.select_related(
                "employee",
                "employee__department_id",
            ).all().order_by("-id")

            if search:
                exits = exits.filter(
                    Q(employee__name__icontains=search)
                )

            if exit_date_from:
                parsed_exit_date_from = parse_date(exit_date_from)
                if parsed_exit_date_from:
                    exits = exits.filter(exit_date__gte=parsed_exit_date_from)

            if exit_date_to:
                parsed_exit_date_to = parse_date(exit_date_to)
                if parsed_exit_date_to:
                    exits = exits.filter(exit_date__lte=parsed_exit_date_to)


            if employee_department:
                if employee_department.isdigit():
                    exits = exits.filter(employee__department_id_id=int(employee_department))
                else:
                    exits = exits.filter(employee__department_id__name__icontains=employee_department)

            paginator = StandardPagination()
            page = paginator.paginate_queryset(exits, request)

            serializer = EmplyeeExitViewSerializer(page, many=True)

            return paginator.get_paginated_response(
                {
                    "status": "success",
                    "message": "Employee exit list fetched successfully",
                    "data": serializer.data
                }
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching employee exits",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EmployeeExitDetailView(BaseTokenView):
    def get_object(self, pk):
        return get_object_or_404(EmployeeExit, pk=pk)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            employee_exit = self.get_object(pk)
            serializer = EmplyeeExitViewSerializer(employee_exit)

            return Response(
                {
                    "status": "success",
                    "message": "Employee exit fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching employee exit",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            employee_exit = self.get_object(pk)

            data = request.data.copy()
            data["created_by"] = authUser.pk

            serializer = EmplyeeExitUpdateSerializer(employee_exit, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Employee exit updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating employee exit",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            employee_exit = self.get_object(pk)
            employee_exit.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Employee exit deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while deleting employee exit",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class SalesTeamListCreateView(BaseTokenView):
    def get(self, request):
        try:
            sales_teams = SalesTeam.objects.all().order_by('-id')
            serializer = SalesTeamSerializer(sales_teams, many=True)
            return Response({
                "success": True,
                "message": "Sales teams fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)

            if error_response:
                return error_response

            data = request.data.copy()
            data['created_by'] = user.id

            serializer = SalesTeamCreateSerializer(data=data)
            if serializer.is_valid():
                serializer.save(created_by=user)
                return Response({
                    "success": True,
                    "message": "Sales team created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SalesTeamDetailUpdateView(BaseTokenView):
    def get(self, request, pk):
        try:
            sales_team = SalesTeam.objects.get(pk=pk)
            serializer = SalesTeamSerializer(sales_team)
            return Response({
                "success": True,
                "message": "Sales team fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except SalesTeam.DoesNotExist:
            return Response({
                "success": False,
                "message": "Sales team not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            sales_team = SalesTeam.objects.get(pk=pk)

            data = request.data.copy()
            serializer = SalesTeamCreateSerializer(sales_team, data=data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "success": True,
                    "message": "Sales team updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except SalesTeam.DoesNotExist:
            return Response({
                "success": False,
                "message": "Sales team not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class SalesTeamMemberListCreateView(BaseTokenView):
    def get(self, request):
        try:
            members = SalesTeamMember.objects.all().order_by('-id')
            serializer = SalesTeamMemberSerializer(members, many=True)
            return Response({
                "success": True,
                "message": "Sales team members fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            user, error_response = self.get_user_from_token(request)

            if error_response:
                return error_response

            data = request.data.copy()
            data['created_by'] = user.id

            serializer = SalesTeamMemberCreateSerializer(data=data)
            if serializer.is_valid():
                serializer.save(created_by=user)
                return Response({
                    "success": True,
                    "message": "Sales team member created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SalesTeamMemberDetailUpdateView(BaseTokenView):
    def get(self, request, pk):
        try:
            member = SalesTeamMember.objects.get(pk=pk)
            serializer = SalesTeamMemberSerializer(member)
            return Response({
                "success": True,
                "message": "Sales team member fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except SalesTeamMember.DoesNotExist:
            return Response({
                "success": False,
                "message": "Sales team member not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            member = SalesTeamMember.objects.get(pk=pk)

            data = request.data.copy()
            serializer = SalesTeamMemberCreateSerializer(member, data=data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response({
                    "success": True,
                    "message": "Sales team member updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "success": False,
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except SalesTeamMember.DoesNotExist:
            return Response({
                "success": False,
                "message": "Sales team member not found"
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class SalesTeamDailyReportView(BaseTokenView):
    """
    GET  -> list only logged-in user's reports
    POST -> create report and save created_by from token
    """
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get('search', '').strip()
            start_date = request.GET.get('start_date', '').strip()
            end_date = request.GET.get('end_date', '').strip()

            reports = SalesTeamDailyReport.objects.filter(
                created_by=authUser
            ).select_related(
                'team', 'created_by', 'state', 'district'
            ).order_by('-id')

            if search:
                reports = reports.filter(
                    Q(team__name__icontains=search) |
                    Q(created_by__name__icontains=search)
                )

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__lte=parsed_end_date)

            paginator = StandardPagination()
            page = paginator.paginate_queryset(reports, request)
            serializer = SalesTeamDailyReportSerializer(page, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Logged-in user sales team daily reports fetched successfully",
                "data": serializer.data
            })

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching sales team daily reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = SalesTeamDailyReportSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(created_by=authUser)
                return Response(
                    {
                        "status": "success",
                        "message": "Sales team daily report created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while creating sales team daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SalesTeamDailyReportDetailView(BaseTokenView):
    """
    GET by id
    PUT by id
    """
    def get_object(self, pk):
        return get_object_or_404(SalesTeamDailyReport, pk=pk)

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk)
            serializer = SalesTeamDailyReportSerializer(report)

            return Response(
                {
                    "status": "success",
                    "message": "Sales team daily report fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching sales team daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk)

            serializer = SalesTeamDailyReportSerializer(report, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Sales team daily report updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating sales team daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SalesTeamDailyReportAllView(BaseTokenView):
    """
    GET -> view all reports with search, date filters, and pagination
    """
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get('search', '').strip()
            start_date = request.GET.get('start_date', '').strip()
            end_date = request.GET.get('end_date', '').strip()

            reports = SalesTeamDailyReport.objects.all().select_related(
                'team', 'created_by', 'state', 'district'
            ).order_by('-id')

            if search:
                reports = reports.filter(
                    Q(team__name__icontains=search) |
                    Q(created_by__name__icontains=search)
                )

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__lte=parsed_end_date)

            paginator = StandardPagination()
            page = paginator.paginate_queryset(reports, request)

            serializer = SalesTeamDailyReportSerializer(page, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "All sales team daily reports fetched successfully",
                "data": serializer.data
            })

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching all sales team daily reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class SalesTeamMemberDailyReportView(BaseTokenView):
    """
    GET  -> logged-in user's own reports (created_by from token)
    POST -> create report and save created_by from token
    """

    def _duration_to_seconds(self, duration_str):
        try:
            if not duration_str:
                return 0
            parts = str(duration_str).split(":")
            if len(parts) != 3:
                return 0
            hours, minutes, seconds = map(int, parts)
            return (hours * 3600) + (minutes * 60) + seconds
        except:
            return 0

    def _seconds_to_hms(self, total_seconds):
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def _get_call_duration_average_8hrs(self, total_seconds, staff_count):
        total_minutes = total_seconds / 60

        if total_minutes <= 0 or staff_count <= 0:
            return 0.0

        return round((total_minutes / (staff_count * 8 * 60)) * 100, 2)

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            call_status = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            state = request.GET.get("state", "").strip()
            district = request.GET.get("district", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            reports = SalesTeamMemberDailyReport.objects.select_related(
                'team',
                'team__division',
                'state',
                'district',
                'created_by',
                'invoice',
                'invoice__customer',
            ).prefetch_related(
                Prefetch(
                    'invoice__items',
                    queryset=OrderItem.objects.select_related('product')
                )
            ).filter(
                created_by=authUser
            ).order_by('-id')

            if search:
                reports = reports.filter(
                    Q(customer_name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(note__icontains=search) |
                    Q(invoice__invoice__icontains=search)
                )

            if call_status:
                reports = reports.filter(call_status__iexact=call_status)

            if status_filter:
                reports = reports.filter(status__iexact=status_filter)

            if state:
                reports = reports.filter(state__name__icontains=state)

            if district:
                reports = reports.filter(district__name__icontains=district)

            parsed_start_date = None
            parsed_end_date = None

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__lte=parsed_end_date)

            if parsed_start_date and parsed_end_date and parsed_start_date > parsed_end_date:
                return Response(
                    {
                        "status": "error",
                        "message": "start_date cannot be greater than end_date"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            total_reports = reports.count()
            active_count = reports.filter(call_status__iexact='active').count()
            productive_count = reports.filter(call_status__iexact='productive').count()

            dsr_created_count = reports.filter(status__iexact='dsr created').count()
            dsr_approved_count = reports.filter(status__iexact='dsr approved').count()
            dsr_confirmed_count = reports.filter(status__iexact='dsr confirmed').count()
            dsr_rejected_count = reports.filter(status__iexact='dsr rejected').count()

            total_call_duration_seconds = 0
            for report in reports:
                total_call_duration_seconds += self._duration_to_seconds(report.call_duration)

            total_call_duration = self._seconds_to_hms(total_call_duration_seconds)

            staff_count = reports.values("created_by").distinct().count()
            call_duration_average_8hrs = self._get_call_duration_average_8hrs(
                total_call_duration_seconds,
                staff_count
            )

            total_amount = reports.aggregate(
                total_amount=Sum('invoice__total_amount')
            )['total_amount'] or 0

            summary = {
                "total_reports": total_reports,
                "active_count": active_count,
                "productive_count": productive_count,
                "dsr_created_count": dsr_created_count,
                "dsr_approved_count": dsr_approved_count,
                "dsr_confirmed_count": dsr_confirmed_count,
                "dsr_rejected_count": dsr_rejected_count,
                "staff_count": staff_count,
                "total_call_duration": total_call_duration,
                "call_duration_average_8hrs": call_duration_average_8hrs,
                "total_amount": float(total_amount),
            }

            paginator = StandardPagination()
            page = paginator.paginate_queryset(reports, request)
            serializer = SalesTeamMemberDailyReportSerializer(
                page,
                many=True,
                context={'request': request}
            )

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Your daily reports fetched successfully",
                "summary": summary,
                "data": serializer.data
            })

        except DatabaseError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Database error occurred while fetching reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching your daily reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            serializer = SalesTeamMemberDailyReportADDSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(created_by=authUser)
                return Response(
                    {
                        "status": "success",
                        "message": "Daily report created successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_201_CREATED
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except DatabaseError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Database error occurred while creating report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while creating daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SalesTeamMemberDailyReportDetailView(BaseTokenView):
    """
    GET    -> single report only if created_by = logged-in user
    PUT    -> update single report only if created_by = logged-in user
    DELETE -> delete single report only if created_by = logged-in user
    """

    def get_object(self, pk, authUser):
        return get_object_or_404(
            SalesTeamMemberDailyReport.objects.select_related(
                'team',
                'state',
                'district',
                'created_by',
                'invoice',
            ),
            pk=pk,
            created_by=authUser
        )

    def get(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk, authUser)
            serializer = SalesTeamMemberDailyReportSerializer(report)

            return Response(
                {
                    "status": "success",
                    "message": "Daily report fetched successfully",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk, authUser)
            serializer = SalesTeamMemberDailyReportADDSerializer(report, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save(created_by=authUser)
                return Response(
                    {
                        "status": "success",
                        "message": "Daily report updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation error",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = self.get_object(pk, authUser)
            report.delete()

            return Response(
                {
                    "status": "success",
                    "message": "Daily report deleted successfully"
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while deleting daily report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class SalesTeamMemberDailyReportAllView(BaseTokenView):
    """
    GET -> all reports with pagination
    """

    def duration_to_seconds(self, duration):
        if not duration:
            return 0
        try:
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except Exception:
            return 0

    def add_call_durations(self, durations):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def get_call_duration_average_8hrs(self, durations, staff_count):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        total_minutes = total_seconds / 60

        if total_minutes <= 0 or staff_count <= 0:
            return 0.0

        return round((total_minutes / (staff_count * 8 * 60)) * 100, 2)

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            call_status = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            created_by = request.GET.get("created_by", "").strip()
            state = request.GET.get("state", "").strip()
            district = request.GET.get("district", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            reports = SalesTeamMemberDailyReport.objects.select_related(
                'team',
                'state',
                'district',
                'created_by',
                'invoice',
            ).all().order_by('-id')

            if search:
                reports = reports.filter(
                    Q(customer_name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(note__icontains=search) |
                    Q(invoice__invoice__icontains=search) |
                    Q(created_by__name__icontains=search)
                )

            if call_status:
                reports = reports.filter(call_status__iexact=call_status)

            if status_filter:
                reports = reports.filter(status__iexact=status_filter)

            if created_by:
                reports = reports.filter(created_by__name__icontains=created_by)

            if state:
                reports = reports.filter(state__name__icontains=state)

            if district:
                reports = reports.filter(district__name__icontains=district)

            parsed_start_date = None
            parsed_end_date = None

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__lte=parsed_end_date)

            if parsed_start_date and parsed_end_date:
                if parsed_start_date > parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "start_date cannot be greater than end_date"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            call_durations = list(reports.values_list("call_duration", flat=True))
            total_call_duration = self.add_call_durations(call_durations)
            staff_count = reports.values("created_by").distinct().count()
            call_duration_average_8hrs = self.get_call_duration_average_8hrs(
                call_durations,
                staff_count
            )

            paginator = StandardPagination()
            page = paginator.paginate_queryset(reports, request)
            serializer = SalesTeamMemberDailyReportSerializer(page, many=True)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "All daily reports fetched successfully",
                "staff_count": staff_count,
                "total_call_duration": total_call_duration,
                "call_duration_average_8hrs": call_duration_average_8hrs,
                "data": serializer.data
            })

        except DatabaseError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Database error occurred while fetching all reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching all daily reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class SalesTeamMemberDailyReportByFamilyView(BaseTokenView):
    """
    GET -> all reports by family_id (division) with pagination
    """

    def duration_to_seconds(self, duration):
        if not duration:
            return 0
        try:
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except Exception:
            return 0

    def add_call_durations(self, durations):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60

        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def get_call_duration_average_8hrs(self, durations, staff_count):
        total_seconds = 0

        for duration in durations:
            if duration:
                total_seconds += self.duration_to_seconds(duration)

        total_minutes = total_seconds / 60

        if total_minutes <= 0 or staff_count <= 0:
            return 0.0

        return round((total_minutes / (staff_count * 8 * 60)) * 100, 2)

    def get(self, request, family_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            search = request.GET.get("search", "").strip()
            call_status = request.GET.get("call_status", "").strip()
            status_filter = request.GET.get("status", "").strip()
            created_by = request.GET.get("created_by", "").strip()
            state = request.GET.get("state", "").strip()
            district = request.GET.get("district", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()

            reports = SalesTeamMemberDailyReport.objects.select_related(
                'team',
                'team__division',
                'state',
                'district',
                'created_by',
                'invoice',
            ).prefetch_related(
                Prefetch(
                    'invoice__items',
                    queryset=OrderItem.objects.select_related('product')
                )
            ).filter(
                team__division_id=family_id
            ).order_by('-id')

            if search:
                reports = reports.filter(
                    Q(customer_name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(note__icontains=search) |
                    Q(invoice__invoice__icontains=search) |
                    Q(created_by__name__icontains=search) |
                    Q(team__name__icontains=search) |
                    Q(state__name__icontains=search) |
                    Q(district__name__icontains=search)
                )

            if call_status:
                reports = reports.filter(call_status__iexact=call_status)

            if status_filter:
                reports = reports.filter(status__iexact=status_filter)

            if created_by:
                reports = reports.filter(created_by__name__icontains=created_by)

            if state:
                reports = reports.filter(state__name__icontains=state)

            if district:
                reports = reports.filter(district__name__icontains=district)

            parsed_start_date = None
            parsed_end_date = None

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__gte=parsed_start_date)

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                reports = reports.filter(created_at__date__lte=parsed_end_date)

            if parsed_start_date and parsed_end_date and parsed_start_date > parsed_end_date:
                return Response(
                    {
                        "status": "error",
                        "message": "start_date cannot be greater than end_date"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            call_durations = list(reports.values_list("call_duration", flat=True))
            total_call_duration = self.add_call_durations(call_durations)
            staff_count = reports.values("created_by").distinct().count()
            call_duration_average_8hrs = self.get_call_duration_average_8hrs(
                call_durations,
                staff_count
            )

            total_amount = reports.aggregate(
                total=Sum('invoice__total_amount')
            )['total'] or 0

            paginator = StandardPagination()
            page = paginator.paginate_queryset(reports, request)
            serializer = SalesTeamMemberDailyReportSerializer(
                page,
                many=True,
                context={'request': request}
            )

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Family wise daily reports fetched successfully",
                "family_id": family_id,
                "staff_count": staff_count,
                "total_call_duration": total_call_duration,
                "call_duration_average_8hrs": call_duration_average_8hrs,
                "total_amount": total_amount, 
                "data": serializer.data
            })

        except DatabaseError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Database error occurred while fetching family wise reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching family wise daily reports",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

class MySalesTeamView(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)

            if error_response:
                return error_response

            sales_teams = SalesTeam.objects.filter(team_leader=user).prefetch_related(
                'members__user'
            ).select_related(
                'team_leader',
                'division',
                'created_by'
            )

            if not sales_teams.exists():
                return Response({
                    "success": True,
                    "is_team_leader": False,
                    "message": "Logged-in user is not a team leader of any sales team",
                    "data": []
                }, status=status.HTTP_200_OK)

            serializer = MySalesTeamListSerializer(sales_teams, many=True)

            return Response({
                "success": True,
                "is_team_leader": True,
                "message": "Sales teams fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MySimpleTeamMembershipView(BaseTokenView):

    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)

            if error_response:
                return error_response

            memberships = SalesTeamMember.objects.filter(user=user).select_related('team')

            if not memberships.exists():
                return Response({
                    "success": True,
                    "is_team_member": False,
                    "message": "User is not part of any sales team",
                    "data": []
                }, status=status.HTTP_200_OK)

            serializer = MySimpleTeamMembershipSerializer(memberships, many=True)

            return Response({
                "success": True,
                "is_team_member": True,
                "message": "User team details fetched successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SalesTeamMembersByTeamView(BaseTokenView):
    def get(self, request, team_id):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            team = SalesTeam.objects.filter(id=team_id).first()
            if not team:
                return Response(
                    {
                        "status": "error",
                        "message": "Sales team not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            members = SalesTeamMember.objects.filter(team_id=team_id).select_related(
                'team', 'user', 'created_by'
            ).order_by('-id')

            serializer = SalesTeamMemberSerializer(members, many=True)

            return Response(
                {
                    "status": "success",
                    "message": "Team members fetched successfully",
                    "team_id": team.id,
                    "team_name": team.name,
                    "count": members.count(),
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching team members",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )




class SalesTeamSummaryReportView(BaseTokenView):
    """
    GET summary report like sheet format

    Filters:
    - status
    - start_date
    - end_date
    - team
    - created_by
    - state
    """

    HOURLY_SLOTS = [
        "09:00-10:00",
        "10:00-11:00",
        "11:00-12:00",
        "12:00-01:00",
        "01:00-02:00",
        "02:00-03:00",
        "03:00-04:00",
        "04:00-05:00",
        "05:00-06:00",
        "06:00-07:00",
    ]

    WORKING_MINUTES = 8 * 60  # 480 minutes

    def get_hour_slot_key(self, created_at):
        if not created_at:
            return None

        local_created_at = timezone.localtime(created_at)
        hour = local_created_at.hour

        if hour == 9:
            return "09:00-10:00"
        elif hour == 10:
            return "10:00-11:00"
        elif hour == 11:
            return "11:00-12:00"
        elif hour == 12:
            return "12:00-01:00"
        elif hour == 13:
            return "01:00-02:00"
        elif hour == 14:
            return "02:00-03:00"
        elif hour == 15:
            return "03:00-04:00"
        elif hour == 16:
            return "04:00-05:00"
        elif hour == 17:
            return "05:00-06:00"
        elif hour == 18:
            return "06:00-07:00"

        return None

    def parse_call_duration(self, value):
        if not value:
            return 0

        try:
            value = str(value).strip().lower()

            # Pure integer seconds like "120"
            if value.isdigit():
                return int(value)

            # Float seconds like "120.0"
            try:
                return int(float(value))
            except:
                pass

            # HH:MM:SS -> "02:04:07"
            if re.match(r'^\d{1,2}:\d{1,2}:\d{1,2}$', value):
                h, m, s = map(int, value.split(':'))
                return h * 3600 + m * 60 + s

            # MM:SS -> "04:07"
            if re.match(r'^\d{1,2}:\d{1,2}$', value):
                m, s = map(int, value.split(':'))
                return m * 60 + s

            # Text formats like "2 min 30 sec"
            hours = re.search(r'(\d+)\s*h(?:our)?s?', value)
            minutes = re.search(r'(\d+)\s*m(?:in)?s?', value)
            seconds = re.search(r'(\d+)\s*s(?:ec)?s?', value)

            total = 0
            if hours:
                total += int(hours.group(1)) * 3600
            if minutes:
                total += int(minutes.group(1)) * 60
            if seconds:
                total += int(seconds.group(1))

            return total

        except:
            return 0

    def get_empty_slot_dict(self):
        return {
            "09:00-10:00": 0,
            "10:00-11:00": 0,
            "11:00-12:00": 0,
            "12:00-01:00": 0,
            "01:00-02:00": 0,
            "02:00-03:00": 0,
            "03:00-04:00": 0,
            "04:00-05:00": 0,
            "05:00-06:00": 0,
            "06:00-07:00": 0,
        }

    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            status_filter = request.GET.get("status", "").strip()
            start_date = request.GET.get("start_date", "").strip()
            end_date = request.GET.get("end_date", "").strip()
            team_id = request.GET.get("team", "").strip()
            created_by_id = request.GET.get("created_by", "").strip()
            state_id = request.GET.get("state", "").strip()
            search = request.GET.get("search", "").strip()

            valid_statuses = [choice[0] for choice in SalesTeamMemberDailyReport.STATUS_CHOICES]
            if status_filter and status_filter not in valid_statuses:
                return Response(
                    {
                        "status": "error",
                        "message": f"Invalid status. Allowed values are: {', '.join(valid_statuses)}"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            parsed_start_date = None
            parsed_end_date = None

            if start_date:
                parsed_start_date = parse_date(start_date)
                if not parsed_start_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid start_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if end_date:
                parsed_end_date = parse_date(end_date)
                if not parsed_end_date:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid end_date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if parsed_start_date and parsed_end_date and parsed_start_date > parsed_end_date:
                return Response(
                    {
                        "status": "error",
                        "message": "start_date cannot be greater than end_date"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            team_daily_qs = SalesTeamDailyReport.objects.select_related(
                'team', 'created_by', 'state', 'district'
            ).all().order_by('-id')

            member_daily_qs = SalesTeamMemberDailyReport.objects.select_related(
                'team', 'state', 'district', 'created_by', 'invoice'
            ).all().order_by('-id')

            if team_id:
                team_daily_qs = team_daily_qs.filter(team_id=team_id)
                member_daily_qs = member_daily_qs.filter(team_id=team_id)

            if created_by_id:
                team_daily_qs = team_daily_qs.filter(created_by_id=created_by_id)
                member_daily_qs = member_daily_qs.filter(created_by_id=created_by_id)

            if state_id:
                team_daily_qs = team_daily_qs.filter(state_id=state_id)
                member_daily_qs = member_daily_qs.filter(state_id=state_id)

            if parsed_start_date:
                team_daily_qs = team_daily_qs.filter(created_at__date__gte=parsed_start_date)
                member_daily_qs = member_daily_qs.filter(created_at__date__gte=parsed_start_date)

            if parsed_end_date:
                team_daily_qs = team_daily_qs.filter(created_at__date__lte=parsed_end_date)
                member_daily_qs = member_daily_qs.filter(created_at__date__lte=parsed_end_date)

            if status_filter:
                member_daily_qs = member_daily_qs.filter(status=status_filter)

            if search:
                member_daily_qs = member_daily_qs.filter(
                    Q(customer_name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(note__icontains=search) |
                    Q(created_by__name__icontains=search) |
                    Q(state__name__icontains=search) |
                    Q(district__name__icontains=search) |
                    Q(team__name__icontains=search)
                )

            grouped = {}

            grand_totals = {
                "team_unbilled": 0,
                "total_unbilled": 0,
                "unbilled_to_billed": 0,
                "new_customer": 0,
                "new_conversion": 0,
                "billing": 0,
                "volume": 0,
                "total_call_duration": 0,
                "hourly_durations": self.get_empty_slot_dict(),
                "call_duration_average_minutes": 0,
                "call_duration_average_percentage": 0,
            }

            total_duration_entries = 0

            # Build from SalesTeamDailyReport
            for item in team_daily_qs:
                team_key = item.team.id if item.team else 0
                team_name = item.team.name if item.team else "No Team"

                if team_key not in grouped:
                    grouped[team_key] = {
                        "team_id": item.team.id if item.team else None,
                        "team_name": team_name,
                        "team_unbilled": 0,
                        "members": {}
                    }

                grouped[team_key]["team_unbilled"] += item.unbilled or 0

                member_key = item.created_by.id
                state_key = f"{item.state.id}_{member_key}"

                if member_key not in grouped[team_key]["members"]:
                    grouped[team_key]["members"][member_key] = {
                        "created_by_id": item.created_by.id,
                        "created_by_name": item.created_by.name,
                        "states": {}
                    }

                if state_key not in grouped[team_key]["members"][member_key]["states"]:
                    grouped[team_key]["members"][member_key]["states"][state_key] = {
                        "state_id": item.state.id,
                        "state_name": item.state.name,
                        "district_id": item.district.id if item.district else None,
                        "district_name": item.district.name if item.district else None,
                        "total_unbilled": 0,
                        "unbilled_to_billed": 0,
                        "new_customer": 0,
                        "new_conversion": 0,
                        "billing": 0,
                        "volume": 0,
                        "total_call_duration": 0,
                        "hourly_durations": self.get_empty_slot_dict()
                    }

                bucket = grouped[team_key]["members"][member_key]["states"][state_key]
                bucket["total_unbilled"] += item.unbilled or 0
                bucket["unbilled_to_billed"] += item.billed or 0
                bucket["new_customer"] += item.new_customers or 0
                bucket["new_conversion"] += item.new_conversions or 0

            # Add member daily report durations and billing
            for item in member_daily_qs:
                team_key = item.team.id if item.team else 0
                team_name = item.team.name if item.team else "No Team"

                if team_key not in grouped:
                    grouped[team_key] = {
                        "team_id": item.team.id if item.team else None,
                        "team_name": team_name,
                        "team_unbilled": 0,
                        "members": {}
                    }

                member_key = item.created_by.id
                state_key = f"{item.state.id}_{member_key}"

                if member_key not in grouped[team_key]["members"]:
                    grouped[team_key]["members"][member_key] = {
                        "created_by_id": item.created_by.id,
                        "created_by_name": item.created_by.name,
                        "states": {}
                    }

                if state_key not in grouped[team_key]["members"][member_key]["states"]:
                    grouped[team_key]["members"][member_key]["states"][state_key] = {
                        "state_id": item.state.id,
                        "state_name": item.state.name,
                        "district_id": item.district.id if item.district else None,
                        "district_name": item.district.name if item.district else None,
                        "total_unbilled": 0,
                        "unbilled_to_billed": 0,
                        "new_customer": 0,
                        "new_conversion": 0,
                        "billing": 0,
                        "volume": 0,
                        "total_call_duration": 0,
                        "hourly_durations": self.get_empty_slot_dict()
                    }

                bucket = grouped[team_key]["members"][member_key]["states"][state_key]

                duration_value_seconds = self.parse_call_duration(item.call_duration)
                duration_value_minutes = round(duration_value_seconds / 60, 2)

                bucket["total_call_duration"] += duration_value_minutes

                if duration_value_minutes > 0:
                    total_duration_entries += 1

                slot_key = self.get_hour_slot_key(item.created_at)
                if slot_key:
                    bucket["hourly_durations"][slot_key] += duration_value_minutes

                if item.invoice_id:
                    bucket["billing"] += 1
                    invoice_amount = getattr(item.invoice, "total_amount", 0) or 0
                    try:
                        bucket["volume"] += float(invoice_amount)
                    except:
                        pass

            response_data = []
            row_number = 1

            for team_key, team_value in grouped.items():
                team_entry = {
                    "sl_no": row_number,
                    "team_id": team_value["team_id"],
                    "team_name": team_value["team_name"],
                    "team_unbilled": team_value["team_unbilled"],
                    "members": []
                }

                grand_totals["team_unbilled"] += team_value["team_unbilled"]

                for member_key, member_value in team_value["members"].items():
                    member_entry = {
                        "created_by_id": member_value["created_by_id"],
                        "created_by_name": member_value["created_by_name"],
                        "states": []
                    }

                    for _, state_value in member_value["states"].items():
                        member_entry["states"].append(state_value)

                        grand_totals["total_unbilled"] += state_value["total_unbilled"]
                        grand_totals["unbilled_to_billed"] += state_value["unbilled_to_billed"]
                        grand_totals["new_customer"] += state_value["new_customer"]
                        grand_totals["new_conversion"] += state_value["new_conversion"]
                        grand_totals["billing"] += state_value["billing"]
                        grand_totals["volume"] += state_value["volume"]
                        grand_totals["total_call_duration"] += state_value["total_call_duration"]

                        for slot in self.HOURLY_SLOTS:
                            grand_totals["hourly_durations"][slot] += state_value["hourly_durations"][slot]

                    team_entry["members"].append(member_entry)

                response_data.append(team_entry)
                row_number += 1

            # Final average calculations
            if total_duration_entries > 0:
                average_minutes = round(grand_totals["total_call_duration"] / total_duration_entries, 2)
            else:
                average_minutes = 0

            average_percentage = round((average_minutes / self.WORKING_MINUTES) * 100, 2) if self.WORKING_MINUTES else 0

            grand_totals["call_duration_average_minutes"] = average_minutes
            grand_totals["call_duration_average_percentage"] = average_percentage

            paginator = StandardPagination()
            page = paginator.paginate_queryset(response_data, request)

            return paginator.get_paginated_response({
                "status": "success",
                "message": "Sales team summary report fetched successfully",
                "filters": {
                    "status": status_filter,
                    "start_date": start_date,
                    "end_date": end_date,
                    "team": team_id,
                    "created_by": created_by_id,
                    "state": state_id,
                    "search": search,
                },
                "data": page,
                "totals": grand_totals
            })

        except DatabaseError as e:
            return Response(
                {
                    "status": "error",
                    "message": "Database error occurred while fetching summary report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while fetching summary report",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class SalesTeamMemberDailyReportStatusUpdateView(BaseTokenView):
    """
    PATCH -> update only status field
    """

    def patch(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            report = SalesTeamMemberDailyReport.objects.get(id=pk)

            serializer = SalesTeamMemberDailyReportStatusUpdateSerializer(
                report,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "message": "Report status updated successfully",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "status": "error",
                    "message": "Validation failed",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except SalesTeamMemberDailyReport.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "message": "Report not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "An error occurred while updating report status",
                    "errors": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )






class FamilyAnalysisSummaryView(BaseTokenView):
    def _parse_duration_to_seconds(self, duration_str):
        try:
            if not duration_str:
                return 0

            parts = str(duration_str).strip().split(":")
            if len(parts) != 3:
                return 0

            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = int(parts[2])

            return (hours * 3600) + (minutes * 60) + seconds
        except Exception:
            return 0

    def get(self, request, *args, **kwargs):
        try:
            user = self.get_user_from_token(request)
            if not user:
                return Response(
                    {
                        "status": "error",
                        "message": "Invalid or missing token"
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            from_date = request.GET.get("from_date", "").strip()
            to_date = request.GET.get("to_date", "").strip()

            attendance_filter = {}
            report_filter = {}

            if from_date and to_date:
                try:
                    from_date_obj = datetime.strptime(from_date, "%Y-%m-%d")
                    to_date_obj = datetime.strptime(to_date, "%Y-%m-%d")
                    to_date_obj = to_date_obj.replace(hour=23, minute=59, second=59)

                    attendance_filter["created_at__range"] = (from_date_obj, to_date_obj)
                    report_filter["created_at__range"] = (from_date_obj, to_date_obj)

                except Exception:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            elif from_date or to_date:
                return Response(
                    {
                        "status": "error",
                        "message": "Both from_date and to_date are required"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            family_map = {}
            families = Family.objects.all().order_by("name")

            for family in families:
                family_map[family.id] = {
                    "family_id": family.id,
                    "family_name": family.name,
                    "present": 0,
                    "absent": 0,
                    "half_day": 0,
                    "total_amount": 0.0,
                    "total_invoices": 0,
                    "total_call_duration_seconds": 0,
                    "call_entries_count": 0,
                }

            attendance_qs = (
                BDMOrderAnalysisStaff.objects
                .filter(staff__family__isnull=False, **attendance_filter)
                .values("staff__family", "staff__family__name", "status")
                .annotate(count=Count("id"))
                .order_by("staff__family__name")
            )

            for item in attendance_qs:
                family_id = item["staff__family"]
                staff_status = item["status"]
                count = item["count"]

                if family_id not in family_map:
                    family_map[family_id] = {
                        "family_id": family_id,
                        "family_name": item["staff__family__name"] or "",
                        "present": 0,
                        "absent": 0,
                        "half_day": 0,
                        "total_amount": 0.0,
                        "total_invoices": 0,
                        "total_call_duration_seconds": 0,
                        "call_entries_count": 0,
                    }

                if staff_status == "present":
                    family_map[family_id]["present"] = count
                elif staff_status == "absent":
                    family_map[family_id]["absent"] = count
                elif staff_status == "half_day":
                    family_map[family_id]["half_day"] = count

            report_invoice_qs = (
                SalesTeamMemberDailyReport.objects
                .filter(
                    created_by__family__isnull=False,
                    invoice__isnull=False,
                    **report_filter
                )
                .values("created_by__family", "created_by__family__name")
                .annotate(
                    total_amount=Sum("invoice__total_amount"),
                    total_invoices=Count("invoice", distinct=True)
                )
                .order_by("created_by__family__name")
            )

            for item in report_invoice_qs:
                family_id = item["created_by__family"]

                if family_id not in family_map:
                    family_map[family_id] = {
                        "family_id": family_id,
                        "family_name": item["created_by__family__name"] or "",
                        "present": 0,
                        "absent": 0,
                        "half_day": 0,
                        "total_amount": 0.0,
                        "total_invoices": 0,
                        "total_call_duration_seconds": 0,
                        "call_entries_count": 0,
                    }

                family_map[family_id]["total_amount"] = float(item["total_amount"] or 0)
                family_map[family_id]["total_invoices"] = int(item["total_invoices"] or 0)

            report_call_qs = (
                SalesTeamMemberDailyReport.objects
                .filter(created_by__family__isnull=False, **report_filter)
                .values(
                    "created_by__family",
                    "created_by__family__name",
                    "call_duration"
                )
                .order_by("created_by__family__name")
            )

            for item in report_call_qs:
                family_id = item["created_by__family"]
                duration_str = item["call_duration"]
                seconds = self._parse_duration_to_seconds(duration_str)

                if family_id not in family_map:
                    family_map[family_id] = {
                        "family_id": family_id,
                        "family_name": item["created_by__family__name"] or "",
                        "present": 0,
                        "absent": 0,
                        "half_day": 0,
                        "total_amount": 0.0,
                        "total_invoices": 0,
                        "total_call_duration_seconds": 0,
                        "call_entries_count": 0,
                    }

                family_map[family_id]["total_call_duration_seconds"] += seconds

                if seconds > 0:
                    family_map[family_id]["call_entries_count"] += 1

            results = []
            overall_present = 0
            overall_absent = 0
            overall_half_day = 0
            overall_total_amount = 0.0
            overall_total_invoices = 0
            overall_total_call_duration_seconds = 0
            overall_call_entries_count = 0

            for _, data in family_map.items():
                total_seconds = data["total_call_duration_seconds"]
                call_entries_count = data["call_entries_count"]

                total_minutes = round(total_seconds / 60, 2) if total_seconds > 0 else 0
                avg_minutes = round((total_seconds / call_entries_count) / 60, 2) if call_entries_count > 0 else 0
                avg_percentage = round((avg_minutes / 480) * 100, 2) if avg_minutes > 0 else 0

                results.append({
                    "family_id": data["family_id"],
                    "family_name": data["family_name"],
                    "present": data["present"],
                    "absent": data["absent"],
                    "half_day": data["half_day"],
                    "total_amount": round(data["total_amount"], 2),
                    "total_invoices": data["total_invoices"],
                    "total_call_count": call_entries_count,
                    "total_call_duration": total_minutes,
                    "call_duration_average_minutes": avg_minutes,
                    "call_duration_average_percentage_8hrs": avg_percentage,
                })

                overall_present += data["present"]
                overall_absent += data["absent"]
                overall_half_day += data["half_day"]
                overall_total_amount += data["total_amount"]
                overall_total_invoices += data["total_invoices"]
                overall_total_call_duration_seconds += total_seconds
                overall_call_entries_count += call_entries_count

            overall_total_minutes = round(overall_total_call_duration_seconds / 60, 2) if overall_total_call_duration_seconds > 0 else 0
            overall_avg_minutes = round((overall_total_call_duration_seconds / overall_call_entries_count) / 60, 2) if overall_call_entries_count > 0 else 0
            overall_avg_percentage = round((overall_avg_minutes / 480) * 100, 2) if overall_avg_minutes > 0 else 0

            return Response(
                {
                    "status": "success",
                    "message": "Family-wise summary fetched successfully",
                    "filters": {
                        "from_date": from_date,
                        "to_date": to_date
                    },
                    "overall": {
                        "present": overall_present,
                        "absent": overall_absent,
                        "half_day": overall_half_day,
                        "total_amount": round(overall_total_amount, 2),
                        "total_invoices": overall_total_invoices,
                        "total_call_count": overall_call_entries_count,
                        "total_call_duration": overall_total_minutes,
                        "call_duration_average_minutes": overall_avg_minutes,
                        "call_duration_average_percentage_8hrs": overall_avg_percentage,
                    },
                    "results": results
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong while fetching family-wise summary",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )





class FamilyStaffAnalysisSummaryView(BaseTokenView):
    def _parse_duration_to_seconds(self, duration_str):
        try:
            if not duration_str:
                return 0

            parts = str(duration_str).strip().split(":")
            if len(parts) != 3:
                return 0

            hours = int(parts[0])
            minutes = int(parts[1])
            seconds = int(parts[2])

            return (hours * 3600) + (minutes * 60) + seconds
        except Exception:
            return 0

    def get(self, request, family_id, *args, **kwargs):
        try:
            user = self.get_user_from_token(request)
            if not user:
                return Response(
                    {
                        "status": "error",
                        "message": "Invalid or missing token"
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            try:
                family = Family.objects.get(id=family_id)
            except Family.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "message": "Family not found"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            from_date = request.GET.get("from_date", "").strip()
            to_date = request.GET.get("to_date", "").strip()

            attendance_filter = {}
            report_filter = {}

            if from_date and to_date:
                try:
                    from_date_obj = datetime.strptime(from_date, "%Y-%m-%d")
                    to_date_obj = datetime.strptime(to_date, "%Y-%m-%d")
                    to_date_obj = to_date_obj.replace(hour=23, minute=59, second=59)

                    attendance_filter["created_at__range"] = (from_date_obj, to_date_obj)
                    report_filter["created_at__range"] = (from_date_obj, to_date_obj)

                except Exception:
                    return Response(
                        {
                            "status": "error",
                            "message": "Invalid date format. Use YYYY-MM-DD"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            elif from_date or to_date:
                return Response(
                    {
                        "status": "error",
                        "message": "Both from_date and to_date are required"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            staff_map = {}

            allowed_staff_qs = User.objects.filter(
                family_id=family_id,
                department_id__name__in=["BDM", "BDO"]
            ).select_related("department_id", "family").order_by("name")

            allowed_staff_ids = list(allowed_staff_qs.values_list("id", flat=True))

            for staff in allowed_staff_qs:
                dept_name = staff.department_id.name if staff.department_id else ""
                staff_map[staff.id] = {
                    "staff_id": staff.id,
                    "staff_name": staff.name,
                    "department": dept_name if dept_name in ["BDM", "BDO"] else "",
                    "present": 0,
                    "absent": 0,
                    "half_day": 0,
                    "total_amount": 0.0,
                    "total_invoices": 0,
                    "total_call_count": 0,
                    "total_call_duration_seconds": 0,
                    "invoice_ids": set(),
                }

            attendance_qs = BDMOrderAnalysisStaff.objects.filter(
                staff_id__in=allowed_staff_ids,
                **attendance_filter
            ).select_related("staff")

            for row in attendance_qs:
                staff_id = row.staff_id

                if staff_id not in staff_map:
                    continue

                if row.status == "present":
                    staff_map[staff_id]["present"] += 1
                elif row.status == "absent":
                    staff_map[staff_id]["absent"] += 1
                elif row.status == "half_day":
                    staff_map[staff_id]["half_day"] += 1

            report_qs = SalesTeamMemberDailyReport.objects.filter(
                created_by_id__in=allowed_staff_ids,
                **report_filter
            ).select_related("created_by", "invoice", "created_by__department_id")

            for report in report_qs:
                staff_id = report.created_by_id

                if staff_id not in staff_map:
                    continue

                seconds = self._parse_duration_to_seconds(report.call_duration)
                if seconds > 0:
                    staff_map[staff_id]["total_call_count"] += 1
                    staff_map[staff_id]["total_call_duration_seconds"] += seconds

                if report.invoice_id and report.invoice_id not in staff_map[staff_id]["invoice_ids"]:
                    staff_map[staff_id]["invoice_ids"].add(report.invoice_id)
                    staff_map[staff_id]["total_invoices"] += 1
                    staff_map[staff_id]["total_amount"] += float(report.invoice.total_amount or 0)

            results = []
            overall_present = 0
            overall_absent = 0
            overall_half_day = 0
            overall_total_amount = 0.0
            overall_total_invoices = 0
            overall_total_call_count = 0
            overall_total_call_duration_seconds = 0

            for _, data in staff_map.items():
                total_seconds = data["total_call_duration_seconds"]
                total_call_count = data["total_call_count"]

                total_call_duration = round(total_seconds / 60, 2) if total_seconds > 0 else 0
                call_duration_average_minutes = round((total_seconds / total_call_count) / 60, 2) if total_call_count > 0 else 0
                call_duration_average_percentage_8hrs = round((call_duration_average_minutes / 480) * 100, 2) if call_duration_average_minutes > 0 else 0

                results.append({
                    "staff_id": data["staff_id"],
                    "staff_name": data["staff_name"],
                    "department": data["department"],
                    "present": data["present"],
                    "absent": data["absent"],
                    "half_day": data["half_day"],
                    "total_amount": round(data["total_amount"], 2),
                    "total_invoices": data["total_invoices"],
                    "total_call_count": total_call_count,
                    "total_call_duration": total_call_duration,
                    "call_duration_average_minutes": call_duration_average_minutes,
                    "call_duration_average_percentage_8hrs": call_duration_average_percentage_8hrs,
                })

                overall_present += data["present"]
                overall_absent += data["absent"]
                overall_half_day += data["half_day"]
                overall_total_amount += data["total_amount"]
                overall_total_invoices += data["total_invoices"]
                overall_total_call_count += total_call_count
                overall_total_call_duration_seconds += total_seconds

            overall_total_call_duration = round(overall_total_call_duration_seconds / 60, 2) if overall_total_call_duration_seconds > 0 else 0
            overall_call_duration_average_minutes = round((overall_total_call_duration_seconds / overall_total_call_count) / 60, 2) if overall_total_call_count > 0 else 0
            overall_call_duration_average_percentage_8hrs = round((overall_call_duration_average_minutes / 480) * 100, 2) if overall_call_duration_average_minutes > 0 else 0

            results = sorted(results, key=lambda x: (x["department"], x["staff_name"].lower() if x["staff_name"] else ""))

            return Response(
                {
                    "status": "success",
                    "message": "Family staff-wise summary fetched successfully",
                    "family": {
                        "family_id": family.id,
                        "family_name": family.name,
                    },
                    "filters": {
                        "from_date": from_date,
                        "to_date": to_date,
                    },
                    "summary": {
                        "present": overall_present,
                        "absent": overall_absent,
                        "half_day": overall_half_day,
                        "total_amount": round(overall_total_amount, 2),
                        "total_invoices": overall_total_invoices,
                        "total_call_count": overall_total_call_count,
                        "total_call_duration": overall_total_call_duration,
                        "call_duration_average_minutes": overall_call_duration_average_minutes,
                        "call_duration_average_percentage_8hrs": overall_call_duration_average_percentage_8hrs,
                    },
                    "results": results
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "message": "Something went wrong while fetching family staff-wise summary",
                    "error": str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class FullHierarchySummaryView(BaseTokenView):

    def _duration_to_seconds(self, duration):
        try:
            if not duration:
                return 0
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def _build_summary(self, reports, attendance_map, team_ids):

        invoice_ids = set()
        bdo_ids = set()
        customers = set()

        total_amount = 0
        total_seconds = 0
        total_call_count = 0
        active = 0
        productive = 0

        present = 0
        absent = 0
        half_day = 0

        for r in reports:

            if r.call_status == "active":
                active += 1
            elif r.call_status == "productive":
                productive += 1

            try:
                if r.created_by.department_id.name == "BDO":
                    bdo_ids.add(r.created_by_id)
            except:
                pass

            try:
                if r.invoice and r.invoice.customer:
                    customers.add(r.invoice.customer.name)
                elif r.customer_name:
                    customers.add(r.customer_name)
            except:
                pass

            if r.invoice_id and r.invoice_id not in invoice_ids:
                invoice_ids.add(r.invoice_id)
                total_amount += float(r.invoice.total_amount or 0)

            sec = self._duration_to_seconds(r.call_duration)
            if sec > 0:
                total_seconds += sec
                total_call_count += 1

            if r.created_by_id in attendance_map:
                present += attendance_map[r.created_by_id]["present"]
                absent += attendance_map[r.created_by_id]["absent"]
                half_day += attendance_map[r.created_by_id]["half_day"]

        total_minutes = total_seconds / 60 if total_seconds else 0
        avg = (total_minutes / total_call_count) if total_call_count else 0
        percent = (avg / 480) * 100 if avg else 0

        return {
            "total_bill": len(invoice_ids),
            "total_volume": round(total_amount, 2),
            "total_call_count": total_call_count,
            "total_call_duration": round(total_minutes, 2),
            "call_duration_average": round(avg, 2),
            "call_duration_percentage_8hrs": round(percent, 2),
            "total_bdo_count": len(bdo_ids),
            "active_count": active,
            "productive_count": productive,
            "unique_customer_count": len(customers),
            "report_count": len(reports),
            "present_count": present,
            "absent_count": absent,
            "half_day_count": half_day,
            "total_team_count": len(team_ids),
        }

    def get(self, request):

        authUser, error = self.get_user_from_token(request)
        if error:
            return error

        staff_ids = list(
            User.objects.filter(
                department_id__name__in=["BDM", "BDO"]
            ).values_list("id", flat=True)
        )
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        reports = SalesTeamMemberDailyReport.objects.select_related(
            "team",
            "created_by",
            "created_by__department_id",
            "invoice",
            "invoice__customer",
        ).filter(created_by_id__in=staff_ids)
        if start_date:
            reports = reports.filter(created_at__date__gte=start_date)
        
        if end_date:
            reports = reports.filter(created_at__date__lte=end_date)

        attendance_map = defaultdict(lambda: {"present": 0, "absent": 0, "half_day": 0})

        for row in BDMOrderAnalysisStaff.objects.filter(staff_id__in=staff_ids):
            if row.status == "present":
                attendance_map[row.staff_id]["present"] += 1
            elif row.status == "absent":
                attendance_map[row.staff_id]["absent"] += 1
            elif row.status == "half_day":
                attendance_map[row.staff_id]["half_day"] += 1

        family_map = {}

        for r in reports:

            if not r.team or not r.created_by.family:
                continue

            fid = r.created_by.family.id
            tid = r.team.id

            if fid not in family_map:
                family_map[fid] = {
                    "family": r.created_by.family,
                    "teams": {}
                }

            if tid not in family_map[fid]["teams"]:
                family_map[fid]["teams"][tid] = []

            family_map[fid]["teams"][tid].append(r)

        families = []
        overall_reports = []
        overall_team_ids = set()

        for fdata in family_map.values():

            team_list = []
            family_reports = []
            team_ids = set()

            for team_id, team_reports in fdata["teams"].items():

                team = team_reports[0].team
                team_ids.add(team.id)

                summary = self._build_summary(
                    team_reports,
                    attendance_map,
                    {team.id}
                )

                team_list.append({
                    "team_id": team.id,
                    "team_name": team.name,
                    "summary": summary
                })

                family_reports.extend(team_reports)

            family_summary = self._build_summary(
                family_reports,
                attendance_map,
                team_ids
            )

            families.append({
                "family_id": fdata["family"].id,
                "family_name": fdata["family"].name,
                "summary": family_summary,
                "teams": team_list
            })

            overall_reports.extend(family_reports)
            overall_team_ids.update(team_ids)

        overall_summary = self._build_summary(
            overall_reports,
            attendance_map,
            overall_team_ids
        )

        response_data = {
            "status": "success",
            "message": "Updated hierarchy summary",
            "summary": overall_summary,
            "families": families
        }

        serializer = FinalHierarchySerializer(response_data)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FamilyDetailedSummaryView(BaseTokenView):

    def _duration_to_seconds(self, duration):
        try:
            if not duration:
                return 0
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def get_empty_slot_dict(self):
        return {
            "09:00-10:00": 0,
            "10:00-11:00": 0,
            "11:00-12:00": 0,
            "12:00-01:00": 0,
            "01:00-02:00": 0,
            "02:00-03:00": 0,
            "03:00-04:00": 0,
            "04:00-05:00": 0,
            "05:00-06:00": 0,
            "06:00-07:00": 0,
        }

    def _build_summary(self, reports, attendance_map, team_ids):

        invoice_ids = set()
        bdo_ids = set()
        customers = set()

        total_bill = 0
        total_seconds = 0
        total_call_count = 0
        active = 0
        productive = 0

        present = 0
        absent = 0
        half_day = 0

        total_unbilled = 0
        billing = 0
        volume = 0
        hourly_durations = self.get_empty_slot_dict()

        new_customers = 0
        new_conversions = 0

        for r in reports:

            if r.call_status == "active":
                active += 1
            elif r.call_status == "productive":
                productive += 1

            try:
                if r.created_by.department_id.name == "BDO":
                    bdo_ids.add(r.created_by_id)
            except:
                pass

            try:
                if r.invoice and r.invoice.customer:
                    customers.add(r.invoice.customer.name)
                elif r.customer_name:
                    customers.add(r.customer_name)
            except:
                pass

            if r.invoice_id and r.invoice_id not in invoice_ids:
                invoice_ids.add(r.invoice_id)
                total_bill += float(r.invoice.total_amount or 0)

            if r.invoice_id:
                billing += 1
                try:
                    volume += float(r.invoice.total_amount or 0)
                except:
                    pass

            sec = self._duration_to_seconds(r.call_duration)

            if sec > 0:
                total_seconds += sec
                total_call_count += 1

                minutes = sec / 60
                hour = localtime(r.created_at).hour
                if hour == 9:
                    hourly_durations["09:00-10:00"] += minutes
                elif hour == 10:
                    hourly_durations["10:00-11:00"] += minutes
                elif hour == 11:
                    hourly_durations["11:00-12:00"] += minutes
                elif hour == 12:
                    hourly_durations["12:00-01:00"] += minutes
                elif hour == 13:
                    hourly_durations["01:00-02:00"] += minutes
                elif hour == 14:
                    hourly_durations["02:00-03:00"] += minutes
                elif hour == 15:
                    hourly_durations["03:00-04:00"] += minutes
                elif hour == 16:
                    hourly_durations["04:00-05:00"] += minutes
                elif hour == 17:
                    hourly_durations["05:00-06:00"] += minutes
                elif hour == 18:
                    hourly_durations["06:00-07:00"] += minutes

            if r.created_by_id in attendance_map:
                present += attendance_map[r.created_by_id]["present"]
                absent += attendance_map[r.created_by_id]["absent"]
                half_day += attendance_map[r.created_by_id]["half_day"]

        if team_ids:
            daily_reports = SalesTeamDailyReport.objects.filter(
                team_id__in=team_ids
            )

            for dr in daily_reports:
                new_customers += dr.new_customers or 0
                new_conversions += dr.new_conversions or 0

        total_minutes = total_seconds / 60 if total_seconds else 0
        avg = (total_minutes / total_call_count) if total_call_count else 0
        percent = (avg / 480) * 100 if avg else 0

        return {
            "total_bill": len(invoice_ids),
            "total_volume": round(total_bill, 2),

            "total_unbilled": total_unbilled,
            "billing": billing,
            "volume": round(volume, 2),
            "hourly_durations": hourly_durations,

            "new_customers": new_customers,
            "new_conversions": new_conversions,

            "total_call_count": total_call_count,
            "total_call_duration": round(total_minutes, 2),
            "call_duration_average": round(avg, 2),
            "call_duration_percentage_8hrs": round(percent, 2),
            "total_bdo_count": len(bdo_ids),
            "active_count": active,
            "productive_count": productive,
            "unique_customer_count": len(customers),
            "report_count": len(reports),

            "present_count": present,
            "absent_count": absent,
            "half_day_count": half_day,
            "total_team_count": len(team_ids),
        }

    def get(self, request, family_id):

        authUser, error = self.get_user_from_token(request)
        if error:
            return error

        staff_qs = User.objects.filter(
            family_id=family_id,
            department_id__name__in=["BDM", "BDO"]
        )

        staff_ids = list(staff_qs.values_list("id", flat=True))

        reports = SalesTeamMemberDailyReport.objects.select_related(
            "team",
            "team__division",
            "created_by",
            "created_by__department_id",
            "invoice",
            "invoice__customer",
        ).filter(created_by_id__in=staff_ids)

        attendance_qs = BDMOrderAnalysisStaff.objects.filter(
            staff_id__in=staff_ids
        )
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        if start_date:
            reports = reports.filter(created_at__date__gte=start_date)

        if end_date:
            reports = reports.filter(created_at__date__lte=end_date)

        attendance_map = defaultdict(lambda: {"present": 0, "absent": 0, "half_day": 0})

        for row in attendance_qs:
            if row.status == "present":
                attendance_map[row.staff_id]["present"] += 1
            elif row.status == "absent":
                attendance_map[row.staff_id]["absent"] += 1
            elif row.status == "half_day":
                attendance_map[row.staff_id]["half_day"] += 1

        team_map = defaultdict(list)

        for r in reports:
            if r.team:
                team_map[r.team.id].append(r)

        teams = []
        all_reports = []
        team_ids = set()

        for team_id, team_reports in team_map.items():
            team = team_reports[0].team
            team_ids.add(team.id)

            summary = self._build_summary(
                team_reports,
                attendance_map,
                {team.id}
            )

            teams.append({
                "team_id": team.id,
                "team_name": team.name,
                "summary": summary
            })

            all_reports.extend(team_reports)

        family_summary = self._build_summary(
            all_reports,
            attendance_map,
            team_ids
        )

        return Response({
            "status": "success",
            "message": "Family detailed summary fetched successfully",
            "family": {
                "family_id": family_id,
                "family_name": staff_qs.first().family.name if staff_qs.exists() else ""
            },
            "summary": family_summary,
            "teams": teams
        }, status=status.HTTP_200_OK)



class TeamDetailedSummaryView(BaseTokenView):

    def _duration_to_seconds(self, duration):
        try:
            if not duration:
                return 0
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def _invoice_total(self, invoice):
        total = Decimal("0.00")
        if not invoice:
            return float(total)

        for item in invoice.items.all():
            rate = Decimal(str(item.rate or 0))
            discount = Decimal(str(item.discount or 0))
            qty = Decimal(str(item.quantity or 0))
            tax = Decimal(str(item.tax or 0))

            base = max(rate - discount, Decimal("0.00")) * qty
            tax_amount = base * tax / Decimal("100")
            total += base + tax_amount

        return float(round(total, 2))

    def get_empty_slot_dict(self):
        return {
            "09:00-10:00": 0,
            "10:00-11:00": 0,
            "11:00-12:00": 0,
            "12:00-01:00": 0,
            "01:00-02:00": 0,
            "02:00-03:00": 0,
            "03:00-04:00": 0,
            "04:00-05:00": 0,
            "05:00-06:00": 0,
            "06:00-07:00": 0,
        }

    def _build_summary(self, reports, attendance_map):

        invoice_ids = set()
        bdo_ids = set()
        customers = set()

        total_bill = 0
        total_seconds = 0
        total_call_count = 0
        active = 0
        productive = 0

        present = 0
        absent = 0
        half_day = 0

        total_unbilled = 0
        billing = 0
        volume = 0
        hourly_durations = self.get_empty_slot_dict()

        new_customers = 0
        new_conversions = 0

        for r in reports:

            if r.call_status == "active":
                active += 1
            elif r.call_status == "productive":
                productive += 1

            try:
                if r.created_by.department_id.name == "BDO":
                    bdo_ids.add(r.created_by_id)
            except:
                pass

            try:
                if r.invoice and r.invoice.customer:
                    customers.add(r.invoice.customer.name)
                elif r.customer_name:
                    customers.add(r.customer_name)
            except:
                pass

            if r.invoice_id and r.invoice_id not in invoice_ids:
                invoice_ids.add(r.invoice_id)

                total_bill += self._invoice_total(r.invoice)

            if r.invoice_id:
                billing += 1
                try:
                    volume += self._invoice_total(r.invoice)
                except:
                    pass

            sec = self._duration_to_seconds(r.call_duration)

            if sec > 0:
                total_seconds += sec
                total_call_count += 1

                minutes = sec / 60
                hour = localtime(r.created_at).hour

                if hour == 9:
                    hourly_durations["09:00-10:00"] += minutes
                elif hour == 10:
                    hourly_durations["10:00-11:00"] += minutes
                elif hour == 11:
                    hourly_durations["11:00-12:00"] += minutes
                elif hour == 12:
                    hourly_durations["12:00-01:00"] += minutes
                elif hour == 13:
                    hourly_durations["01:00-02:00"] += minutes
                elif hour == 14:
                    hourly_durations["02:00-03:00"] += minutes
                elif hour == 15:
                    hourly_durations["03:00-04:00"] += minutes
                elif hour == 16:
                    hourly_durations["04:00-05:00"] += minutes
                elif hour == 17:
                    hourly_durations["05:00-06:00"] += minutes
                elif hour == 18:
                    hourly_durations["06:00-07:00"] += minutes

            if r.created_by_id in attendance_map:
                present += attendance_map[r.created_by_id]["present"]
                absent += attendance_map[r.created_by_id]["absent"]
                half_day += attendance_map[r.created_by_id]["half_day"]

        team_ids = list(set([r.team_id for r in reports if r.team_id]))

        if team_ids:
            daily_reports = SalesTeamDailyReport.objects.filter(
                team_id__in=team_ids
            )

            for dr in daily_reports:
                new_customers += dr.new_customers or 0
                new_conversions += dr.new_conversions or 0

        total_minutes = total_seconds / 60 if total_seconds else 0
        avg = (total_minutes / total_call_count) if total_call_count else 0
        percent = (avg / 480) * 100 if avg else 0

        return {
            "total_bill": len(invoice_ids),
            "total_volume": round(total_bill, 2),

            "total_unbilled": total_unbilled,
            "billing": billing,
            "volume": round(volume, 2),
            "hourly_durations": hourly_durations,

            "new_customers": new_customers,
            "new_conversions": new_conversions,

            "total_call_count": total_call_count,
            "total_call_duration": round(total_minutes, 2),
            "call_duration_average": round(avg, 2),
            "call_duration_percentage_8hrs": round(percent, 2),
            "total_bdo_count": len(bdo_ids),
            "active_count": active,
            "productive_count": productive,
            "unique_customer_count": len(customers),
            "report_count": len(reports),

            "present_count": present,
            "absent_count": absent,
            "half_day_count": half_day,
            "total_team_count": 1,
        }

    def get(self, request, team_id):

        authUser, error = self.get_user_from_token(request)
        if error:
            return error

        reports = SalesTeamMemberDailyReport.objects.select_related(
            "team",
            "created_by",
            "created_by__department_id",
            "invoice",
            "invoice__manage_staff",
            "invoice__warehouses",
            "invoice__company",
            "invoice__customer",
            "invoice__billing_address",
            "invoice__family",
            "invoice__state",
            "invoice__locked_by",
            "state",
            "district",
        ).prefetch_related(
            Prefetch(
                "invoice__items",
                queryset=OrderItem.objects.select_related(
                    "product",
                    "size",
                    "variant",
                )
            )
        ).filter(team_id=team_id)

        search = request.GET.get("search", "").strip()
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        if search:
            reports = reports.filter(
                Q(created_by__name__icontains=search) |
                Q(phone__icontains=search) |
                Q(customer_name__icontains=search) |
                Q(invoice__invoice__icontains=search)
            )

        if start_date:
            reports = reports.filter(created_at__date__gte=start_date)

        if end_date:
            reports = reports.filter(created_at__date__lte=end_date)
        
        staff_id = request.GET.get("staff_id")
        state_id = request.GET.get("state_id")
        district_id = request.GET.get("district_id")
        invoice_id = request.GET.get("invoice_id")
        customer_id = request.GET.get("customer_id")


        if staff_id:
            reports = reports.filter(created_by_id=staff_id)

        if state_id:
            reports = reports.filter(state_id=state_id)

        if district_id:
            reports = reports.filter(district_id=district_id)


        if invoice_id:
            reports = reports.filter(invoice_id=invoice_id)

     
        if customer_id:
            reports = reports.filter(invoice__customer_id=customer_id)

        if not reports.exists():
            return Response({
                "status": "success",
                "message": "No data found",
                "team": {"team_id": team_id},
                "summary": {},
                "members": []
            })

        team = reports.first().team

        staff_ids = list(reports.values_list("created_by_id", flat=True).distinct())

        attendance_qs = BDMOrderAnalysisStaff.objects.filter(
            staff_id__in=staff_ids
        )

        attendance_map = defaultdict(lambda: {"present": 0, "absent": 0, "half_day": 0})

        for row in attendance_qs:
            if row.status == "present":
                attendance_map[row.staff_id]["present"] += 1
            elif row.status == "absent":
                attendance_map[row.staff_id]["absent"] += 1
            elif row.status == "half_day":
                attendance_map[row.staff_id]["half_day"] += 1

        member_map = defaultdict(list)

        for r in reports:
            member_map[r.created_by_id].append(r)

        members = []

        for staff_id, staff_reports in member_map.items():
            staff = staff_reports[0].created_by

            members.append({
                "staff_id": staff.id,
                "staff_name": staff.name,
                "summary": self._build_summary(staff_reports, attendance_map),
                "reports": TeamMemberReportSerializer(staff_reports, many=True).data,
            })

        paginator = StandardPagination()
        page = paginator.paginate_queryset(members, request)

        team_summary = self._build_summary(reports, attendance_map)

        return paginator.get_paginated_response({
            "status": "success",
            "message": "Team detailed summary fetched",
            "team": {
                "team_id": team.id,
                "team_name": team.name
            },
            "summary": team_summary,
            "members": page
        })


class MyTeamDetailedSummaryView(BaseTokenView):

    def _duration_to_seconds(self, duration):
        try:
            if not duration:
                return 0
            h, m, s = map(int, str(duration).split(":"))
            return h * 3600 + m * 60 + s
        except:
            return 0

    def _invoice_total(self, invoice):
        total = Decimal("0.00")
        if not invoice:
            return float(total)

        for item in invoice.items.all():
            rate = Decimal(str(item.rate or 0))
            discount = Decimal(str(item.discount or 0))
            qty = Decimal(str(item.quantity or 0))
            tax = Decimal(str(item.tax or 0))

            base = max(rate - discount, Decimal("0.00")) * qty
            tax_amount = base * tax / Decimal("100")
            total += base + tax_amount

        return float(round(total, 2))

    def get_empty_slot_dict(self):
        return {
            "09:00-10:00": 0,
            "10:00-11:00": 0,
            "11:00-12:00": 0,
            "12:00-01:00": 0,
            "01:00-02:00": 0,
            "02:00-03:00": 0,
            "03:00-04:00": 0,
            "04:00-05:00": 0,
            "05:00-06:00": 0,
            "06:00-07:00": 0,
        }

    def _build_summary(self, reports, attendance_map):
        invoice_ids = set()
        bdo_ids = set()
        customers = set()

        total_bill = 0
        total_seconds = 0
        total_call_count = 0
        active = 0
        productive = 0

        present = 0
        absent = 0
        half_day = 0

        total_unbilled = 0
        billing = 0
        volume = 0
        hourly_durations = self.get_empty_slot_dict()

        new_customers = 0
        new_conversions = 0

        for r in reports:
            if r.call_status == "active":
                active += 1
            elif r.call_status == "productive":
                productive += 1

            try:
                if r.created_by.department_id.name == "BDO":
                    bdo_ids.add(r.created_by_id)
            except:
                pass

            try:
                if r.invoice and r.invoice.customer:
                    customers.add(r.invoice.customer.name)
                elif r.customer_name:
                    customers.add(r.customer_name)
            except:
                pass

            if r.invoice_id and r.invoice_id not in invoice_ids:
                invoice_ids.add(r.invoice_id)
                total_bill += self._invoice_total(r.invoice)

            if r.invoice_id:
                billing += 1
                try:
                    volume += self._invoice_total(r.invoice)
                except:
                    pass

            sec = self._duration_to_seconds(r.call_duration)

            if sec > 0:
                total_seconds += sec
                total_call_count += 1

                minutes = sec / 60
                hour = localtime(r.created_at).hour

                if hour == 9:
                    hourly_durations["09:00-10:00"] += minutes
                elif hour == 10:
                    hourly_durations["10:00-11:00"] += minutes
                elif hour == 11:
                    hourly_durations["11:00-12:00"] += minutes
                elif hour == 12:
                    hourly_durations["12:00-01:00"] += minutes
                elif hour == 13:
                    hourly_durations["01:00-02:00"] += minutes
                elif hour == 14:
                    hourly_durations["02:00-03:00"] += minutes
                elif hour == 15:
                    hourly_durations["03:00-04:00"] += minutes
                elif hour == 16:
                    hourly_durations["04:00-05:00"] += minutes
                elif hour == 17:
                    hourly_durations["05:00-06:00"] += minutes
                elif hour == 18:
                    hourly_durations["06:00-07:00"] += minutes

            if r.created_by_id in attendance_map:
                present += attendance_map[r.created_by_id]["present"]
                absent += attendance_map[r.created_by_id]["absent"]
                half_day += attendance_map[r.created_by_id]["half_day"]

        team_ids = list(set([r.team_id for r in reports if r.team_id]))

        if team_ids:
            daily_reports = SalesTeamDailyReport.objects.filter(team_id__in=team_ids)

            for dr in daily_reports:
                new_customers += dr.new_customers or 0
                new_conversions += dr.new_conversions or 0

        total_minutes = total_seconds / 60 if total_seconds else 0
        avg = (total_minutes / total_call_count) if total_call_count else 0
        percent = (avg / 480) * 100 if avg else 0

        return {
            "total_bill": len(invoice_ids),
            "total_volume": round(total_bill, 2),

            "total_unbilled": total_unbilled,
            "billing": billing,
            "volume": round(volume, 2),
            "hourly_durations": hourly_durations,

            "new_customers": new_customers,
            "new_conversions": new_conversions,

            "total_call_count": total_call_count,
            "total_call_duration": round(total_minutes, 2),
            "call_duration_average": round(avg, 2),
            "call_duration_percentage_8hrs": round(percent, 2),
            "total_bdo_count": len(bdo_ids),
            "active_count": active,
            "productive_count": productive,
            "unique_customer_count": len(customers),
            "report_count": len(reports),

            "present_count": present,
            "absent_count": absent,
            "half_day_count": half_day,
            "total_team_count": 1,
        }

    def get(self, request):
        try:
            authUser, error = self.get_user_from_token(request)
            if error:
                return error

            sales_teams = SalesTeam.objects.filter(team_leader=authUser).select_related(
                "team_leader",
                "division",
                "created_by"
            )

            if not sales_teams.exists():
                return Response({
                    "success": True,
                    "is_team_leader": False,
                    "message": "Logged-in user is not a team leader of any sales team",
                    "data": []
                }, status=status.HTTP_200_OK)

            team_ids = list(sales_teams.values_list("id", flat=True))

            reports = SalesTeamMemberDailyReport.objects.select_related(
                "team",
                "created_by",
                "created_by__department_id",
                "created_by__family",
                "invoice",
                "invoice__manage_staff",
                "invoice__warehouses",
                "invoice__company",
                "invoice__customer",
                "invoice__billing_address",
                "invoice__family",
                "invoice__state",
                "invoice__locked_by",
                "state",
                "district",
            ).prefetch_related(
                Prefetch(
                    "invoice__items",
                    queryset=OrderItem.objects.select_related(
                        "product",
                        "size",
                        "variant",
                    )
                )
            ).filter(team_id__in=team_ids)

            search = request.GET.get("search", "").strip()
            start_date = request.GET.get("start_date")
            end_date = request.GET.get("end_date")
            staff_id = request.GET.get("staff_id")
            state_id = request.GET.get("state_id")
            district_id = request.GET.get("district_id")
            invoice_id = request.GET.get("invoice_id")
            customer_id = request.GET.get("customer_id")
            team_id = request.GET.get("team_id")

            if team_id:
                reports = reports.filter(team_id=team_id)

            if search:
                reports = reports.filter(
                    Q(created_by__name__icontains=search) |
                    Q(phone__icontains=search) |
                    Q(customer_name__icontains=search) |
                    Q(invoice__invoice__icontains=search) |
                    Q(team__name__icontains=search)
                )

            if start_date:
                reports = reports.filter(created_at__date__gte=start_date)

            if end_date:
                reports = reports.filter(created_at__date__lte=end_date)

            if staff_id:
                reports = reports.filter(created_by_id=staff_id)

            if state_id:
                reports = reports.filter(state_id=state_id)

            if district_id:
                reports = reports.filter(district_id=district_id)

            if invoice_id:
                reports = reports.filter(invoice_id=invoice_id)

            if customer_id:
                reports = reports.filter(invoice__customer_id=customer_id)

            if not reports.exists():
                return Response({
                    "success": True,
                    "is_team_leader": True,
                    "message": "No data found",
                    "data": []
                }, status=status.HTTP_200_OK)

            staff_ids = list(reports.values_list("created_by_id", flat=True).distinct())

            attendance_qs = BDMOrderAnalysisStaff.objects.filter(
                staff_id__in=staff_ids
            )

            attendance_map = defaultdict(lambda: {"present": 0, "absent": 0, "half_day": 0})

            for row in attendance_qs:
                if row.status == "present":
                    attendance_map[row.staff_id]["present"] += 1
                elif row.status == "absent":
                    attendance_map[row.staff_id]["absent"] += 1
                elif row.status == "half_day":
                    attendance_map[row.staff_id]["half_day"] += 1

            team_wise_reports = defaultdict(list)
            for r in reports:
                team_wise_reports[r.team_id].append(r)

            final_data = []

            for team in sales_teams:
                team_reports = team_wise_reports.get(team.id, [])

                if not team_reports:
                    final_data.append({
                        "team": {
                            "team_id": team.id,
                            "team_name": team.name
                        },
                        "summary": {},
                        "members": []
                    })
                    continue

                member_map = defaultdict(list)
                for r in team_reports:
                    member_map[r.created_by_id].append(r)

                members = []

                for member_staff_id, staff_reports in member_map.items():
                    staff = staff_reports[0].created_by

                    members.append({
                        "staff_id": staff.id,
                        "staff_name": staff.name,
                        "summary": self._build_summary(staff_reports, attendance_map),
                        "reports": TeamMemberReportSerializer(staff_reports, many=True).data,
                    })

                final_data.append({
                    "team": {
                        "team_id": team.id,
                        "team_name": team.name
                    },
                    "summary": self._build_summary(team_reports, attendance_map),
                    "members": members
                })

            return Response({
                "success": True,
                "is_team_leader": True,
                "message": "My team detailed summary fetched successfully",
                "data": final_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "success": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)