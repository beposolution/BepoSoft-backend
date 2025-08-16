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
from datetime import datetime, timedelta
from django.db.models import Q
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.contrib.auth import authenticate
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import DatabaseError
from decimal import Decimal
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
from datetime import date
from rest_framework.pagination import PageNumberPagination
from bepocart.models import *
from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)


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
        
class StaffOrders(BaseTokenView):
    def get(self, request):
        try:
            user, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Assuming 'created_at' is the date field you want to sort by
            orders = Order.objects.filter(manage_staff=user.pk).order_by('-id')

            serialized_orders = OrderModelSerilizer(orders, many=True)

            return Response({
                "message": "Orders fetched successfully",
                "data": serialized_orders.data
            }, status=status.HTTP_200_OK)

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

class CustomerView(BaseTokenView):
   
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            customers = Customers.objects.all().order_by('-created_at') 
            serializer = CustomerModelSerializerLimited(customers, many=True)
            return Response({"data": serializer.data, "message": "Customers retrieved successfully"}, status=status.HTTP_200_OK)

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
            products = Products.objects.all()
            serializer = ProductsListViewSerializers(products, many=True)
            return Response({"data": serializer.data}, status=status.HTTP_200_OK)
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

            
#             order_ser = OrderSerializer(data=request.data)
#             order_ser.is_valid(raise_exception=True)

           
#             items = request.data.get("items", [])
#             if not items:
#                 return Response(
#                     {"status": "error", "message": "No line items with rack_allocations were provided."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )

#             order = order_ser.save()

#             product_ids = {int(i["product"]) for i in items if "product" in i}
#             list(Products.objects.select_for_update().filter(pk__in=product_ids))

#             for line in items:
#                 line_payload = {
#                     "product": line["product"],
#                     "variant": line.get("variant"),
#                     "size": line.get("size"),
#                     "description": line.get("description", ""),
#                     "rate": line["rate"],
#                     "discount": line.get("discount", 0),
#                     "tax": line.get("tax", 0),
#                     "quantity": line["quantity"],
#                     "rack_allocations": line["rack_allocations"],
#                 }
#                 oi_ser = OrderItemCreateSerializer(data=line_payload, context={"order": order})
#                 oi_ser.is_valid(raise_exception=True)
#                 oi_ser.save() 

#             BeposoftCart.objects.filter(user=authUser).delete()

#             return Response(
#                 {"status": "success", "message": "Order created successfully", "data": OrderSerializer(order).data},
#                 status=status.HTTP_201_CREATED
#             )

#         except serializers.ValidationError as ve:
#             return Response({"status": "error", "errors": ve.detail}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             logger.exception("Unexpected error during order creation")
#             transaction.set_rollback(True)
#             return Response(
#                 {"status": "error", "message": "An unexpected error occurred", "errors": str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
            
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

#             # Lock all products in one go
#             products = Products.objects.select_for_update().filter(pk__in=product_ids)
#             products_map = {p.pk: p for p in products}

#             # Create order items and update locked_stock once per product
#             for product_id, data in product_data.items():
#                 # Create order item
#                 OrderItem.objects.create(
#                     order=order,
#                     product=data["product"],
#                     quantity=int(data["quantity"]),
#                     discount=data["discount"],
#                     tax=data["tax"],
#                     rate=data["rate"],
#                     description=data["description"],
                    
#                 )
#                 product = products_map[product_id]

#                 old_locked_stock = product.locked_stock or 0
#                 product.locked_stock = old_locked_stock + data["quantity"]
#                 product.save()

#             # Clear cart after order creation
#             cart_items.delete()
#             return Response({"status": "success", "message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

#         except Exception as e:
#             logger.error(f"Unexpected error during order creation: {e}", exc_info=True)
#             traceback.print_exc()
#             return Response({"status": "error", "message": "An unexpected error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from beposoft_app.utils.racks import allocate_racks_for_quantity, RackAllocationError

class CreateOrder(BaseTokenView):
    @transaction.atomic
    def post(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            cart_items = BeposoftCart.objects.filter(user=authUser)
            if not cart_items.exists():
                return Response({"status": "error", "message": " Cart is empty"}, status=status.HTTP_400_BAD_REQUEST)

            serializer = OrderSerializer(data=request.data)
            if not serializer.is_valid():
                return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            order = serializer.save()

            # Aggregate per-product
            product_data = {}
            product_ids = set()
            for item in cart_items:
                pid = item.product.pk
                product_ids.add(pid)
                if pid not in product_data:
                    product_data[pid] = {
                        "product": item.product,
                        "quantity": int(item.quantity),
                        "discount": Decimal(item.discount or 0),
                        "tax": Decimal(item.product.tax or 0),
                        "rate": Decimal(item.price or 0),
                        "description": item.note,
                    }
                else:
                    product_data[pid]["quantity"] += int(item.quantity)
                    product_data[pid]["discount"] += Decimal(item.discount or 0)

            # Lock products for concurrency safety
            products = Products.objects.select_for_update().filter(pk__in=product_ids)
            products_map = {p.pk: p for p in products}

            # Create items with auto rack allocation
            for pid, data in product_data.items():
                product = products_map[pid]
                qty = data["quantity"]

                # 1) allocate racks
                try:
                    allocations = allocate_racks_for_quantity(product, qty)
                except RackAllocationError as e:
                    raise serializers.ValidationError({"rack_allocation": str(e)})

                # 2) create order item WITH allocations so your pre_save signal locks racks
                OrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=qty,
                    discount=data["discount"],
                    tax=data["tax"],
                    rate=data["rate"],
                    description=data["description"],
                    rack_details=allocations,      # <<< important
                )

                # 3) DO NOT manually increment locked_stock here;
                #     OrderItem.save() already updates product.locked_stock.

            # Clear cart
            cart_items.delete()
            return Response({"status": "success", "message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as ve:
            return Response({"status": "error", "message": "Validation failed", "errors": ve.detail}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error during order creation: {e}", exc_info=True)
            traceback.print_exc()
            return Response({"status": "error", "message": "An unexpected error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

            # Optimize Query and Order by order_date descending
            orders = Order.objects.select_related(
                "manage_staff", "customer", "state", "family"
            ).prefetch_related("warehouse").order_by("-id")

            # Optimize Count Queries
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


class TrackingReport(BaseTokenView):
    def get(self, request):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Optimize Query and Order by order_date descending
            orders = Order.objects.select_related(
                "manage_staff", "customer", "state", "family"
            ).prefetch_related("warehouse").order_by("-id")

            # Optimize Count Queries
            invoice_counts = orders.aggregate(
                invoice_created_count=Count("id", filter=Q(status="Invoice Created")),
                invoice_approved_count=Count("id", filter=Q(status="Waiting For Confirmation"))
            )

            serializer = TrackingdetailsSerializer(orders, many=True)

            # Add family_id and family_name to each order in results
            results = serializer.data
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
            
            manage_staff_designation = order.manage_staff.designation
            orderSerilizer = OrderModelSerilizer(order, many=False)
            serializer = OrderItemModelSerializer(orderItems, many=True, context={'manage_staff_designation': manage_staff_designation})

            return Response({"order": orderSerilizer.data, "items": serializer.data}, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({"status": "error", "message": "Orders not found"}, status=status.HTTP_404_NOT_FOUND)
        except DatabaseError:
            return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        



logger = logging.getLogger(__name__)


# class CustomerOrderStatusUpdate(BaseTokenView):
#     @transaction.atomic
#     def put(self, request, pk):
#         authUser, error_response = self.get_user_from_token(request)
#         if error_response:
#             return error_response

#         try:
#             order = Order.objects.select_for_update().filter(pk=pk).first()
#             if not order:
#                 return Response({"status": "error", "message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

#             new_status = request.data.get('status')
#             if not new_status:
#                 return Response({"status": "error", "message": "Status field is required"}, status=status.HTTP_400_BAD_REQUEST)

#             locked_stock_updates = {}

#             # ✅ Aggregate quantities by product
#             if new_status in ["Shipped", "Invoice Rejected"]:
#                 for item in order.items.all():
#                     product = Products.objects.select_for_update().filter(pk=item.product.pk).first()
#                     if not product:
#                         return Response({"status": "error", "message": "Product not found"}, status=status.HTTP_404_NOT_FOUND)

#                     # Accumulate quantities for this product
#                     if product.pk in locked_stock_updates:
#                         locked_stock_updates[product.pk] += item.quantity
#                     else:
#                         locked_stock_updates[product.pk] = item.quantity
#                 # ✅ Apply the updates
#                 for product_id, qty_to_release in locked_stock_updates.items(): 
#                     product = Products.objects.get(pk=product_id)
#                     if product.locked_stock < 0:
#                         logger.warning(f"Product {product_id} had negative locked_stock ({product.locked_stock}), resetting to 0.")
#                         product.locked_stock = 0
#                         product.save()
#                     if product.locked_stock < qty_to_release:
#                         return Response(
#                             {
#                                 "status": "error",
#                                 "message": "Locked stock inconsistency detected!",
#                                 "product_id": product_id,
#                                 "locked_stock": product.locked_stock,
#                                 "qty_to_release": qty_to_release,
#                                 "order_id": order.pk
#                             },
#                             status=status.HTTP_400_BAD_REQUEST
#                         )
#                     product.locked_stock -= qty_to_release
#                     if new_status == "Shipped":
#                         product.stock -= qty_to_release
#                     product.save()

#             order.status = new_status
#             order.save()

#             return Response({"status": "success", "message": "Order status updated successfully"}, status=status.HTTP_200_OK)

#         except DatabaseError as db_err:
#             logger.error(f"Database error: {db_err}", exc_info=True)
#             return Response({"status": "error", "message": "Database error occurred", "error": str(db_err)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except Exception as e:
#             logger.error(f"Unexpected error: {e}", exc_info=True)
#             return Response({"status": "error", "messaaage": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



        
# class ShippingManagementView(BaseTokenView):
#     def put(self,request,pk):
#         try:
#             authUser, error_response = self.get_user_from_token(request)
#             if error_response:
#                 return error_response

#             order = Order.objects.filter(pk=pk).first()
#             if not order:
#                 return Response({"status": "error", "message": "Order not found"}, status=status.HTTP_404_NOT_FOUND)

#             old_status = order.status
#             new_status = request.data.get("status", old_status)
            
#             serializer = OrderSerializer(order, data=request.data, partial=True)
#             if serializer.is_valid():
#                 serializer.save()

#                 if old_status != "Invoice Rejected" and new_status == "Invoice Rejected":
#                     for item in order.items.all():  # Assuming a related_name 'order_items'
#                         product = item.product
#                         product.locked_stock = max(product.locked_stock - item.quantity, 0)
#                         product.save()

#                 return Response({"status": "success", "message": "Order updated successfully"}, status=status.HTTP_200_OK)
#             return Response({"status": "error", "message": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
        
#         except DatabaseError:
#             return Response({"status": "error", "message": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except Exception as e:
#             return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
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

            # ✅ make the update atomic so Order.save() can use select_for_update()
            with transaction.atomic():
                serializer = OrderSerializer(order, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()

                    # (Optional) you don't need this block anymore because your Order.save()
                    # already releases locked_stock when status becomes "Invoice Rejected".
                    # If you keep it, also keep it inside the same transaction.
                    # if old_status != "Invoice Rejected" and new_status == "Invoice Rejected":
                    #     for item in order.items.all():
                    #         product = item.product
                    #         product.locked_stock = max(product.locked_stock - item.quantity, 0)
                    #         product.save(update_fields=["locked_stock"])

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
    def delete(self,request,pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            order_item = self.get_order_item(pk)
            if not order_item:
                return Response({"status": "error", "message": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)
            order_item.delete()
            return Response({"status": "success"}, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
                        
            item = self.get_order_item(pk)
            if not item:
                return Response({"status": "error", "message": "Order item not found"}, status=status.HTTP_404_NOT_FOUND)
            serializer = ExistedOrderAddProductsSerializer(item, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"status": "success", "message": "Order item updated successfully"}, status=status.HTTP_200_OK)
            return Response({"status": "error", "message": "Invalid data provided"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e :
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Fetch customer
            customer = get_object_or_404(Customers, pk=pk)

            # Fetch order ledger
            ledger = Order.objects.filter(customer=customer.pk).order_by("order_date")
            ledger_serializer = LedgerSerializers(ledger, many=True)

            # Fetch advance receipts for the customer (if related to customer)
            advance_receipts = AdvanceReceipt.objects.filter(customer=customer).order_by('-id')
            advance_serializer = AdvanceReceiptSerializer(advance_receipts, many=True)

            # Return combined response
            return Response(
                {
                    "data": {
                        "ledger": ledger_serializer.data,
                        "advance_receipts": advance_serializer.data
                    }
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response({"errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
     
            
class CreatePerfomaInvoice(BaseTokenView):
    def post(self, request):
        try:
            # Authenticate user
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            warehouse_id = request.data.get("warehouse_id")
            if not warehouse_id:
                return Response({"status": "error", "message": "Warehouse ID is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Retrieve and validate the warehouse object
            warehouse = get_object_or_404(WareHouse, pk=warehouse_id)
            cart_items = BeposoftCart.objects.filter(user=authUser)
            serializer = PerfomaInvoiceOrderSerializers(data=request.data)
            if not serializer.is_valid():
                return Response({"status": "error", "message": "Validation failed", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
         # Retrieve cart items and validate serializer
            
              # Create order
            order = serializer.save()

            # Manually assign the warehouse to the order
            order.warehouses_obj = warehouse
            order.save()  
            for item_data in cart_items:
                product = get_object_or_404(Products, pk=item_data.product.pk)

                # Convert values to Decimal for consistency
                quantity = Decimal(item_data.quantity or 0)
                selling_price = Decimal(item_data.product.selling_price or 0)
                discount = Decimal(item_data.discount or 0)  # Handles None discount
                tax = Decimal(item_data.product.tax or 0)
                rate = Decimal(item_data.product.selling_price or 0)
               

                

                # Check stock and decrement
                if product.stock < quantity:
                    return Response({"status": "error", "message": "Insufficient stock for single product"}, status=status.HTTP_400_BAD_REQUEST)
                product.stock -= int(quantity)
                product.save()
            
               

                # Create order item for each valid cart item
                PerfomaInvoiceOrderItem.objects.create(
                    order=order,
                    product=product,
                    quantity=int(quantity),
                    discount=discount,
                    tax=tax,
                    rate=rate,
                    description=item_data.note,
                )
            
            # Clear cart after successful order creation
            cart_items.delete()
            return Response({"status": "success", "message": "Order created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            logger.error("Unexpected error in CreateOrder view: %s", str(e))
            return Response({"status": "error", "message": "An unexpected error occurred", "errors": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

from django.shortcuts import get_object_or_404

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
                        "warehouses": [warehouse]
                    })
                    
            # Convert dictionary to list format
            formatted_response = list(grouped_families.values())
            return Response({"results": formatted_response}, status=status.HTTP_200_OK)   

        except Exception as e:
            return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
            # Authenticate the user using the token
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response

            # Ensure the request data is a list of dictionaries
            data = request.data if isinstance(request.data, list) else [request.data]

            # Use the serializer with `many=True` for lists
            grvdata = GRVModelSerializer(data=data, many=True)

            # Validate and save the data
            if grvdata.is_valid():
                grvdata.save()
                return Response({
                    "status": "success",
                    "message": "Added successfully",
                    "data": grvdata.data
                }, status=status.HTTP_200_OK)

            logger.error(f"Validation failed: {grvdata.errors}")
            return Response({
                "status": "error",
                "message": "Validation failed",
                "errors": grvdata.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error occurred in GRVaddView: {str(e)}")
            return Response({
                "status": "error",
                "message": "An error occurred while processing the request",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
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
            


class GRVUpdateView(BaseTokenView):
    def put(self, request, pk):
        try:
            authUser, error_response = self.get_user_from_token(request)
            if error_response:
                return error_response
            grv = get_object_or_404(GRVModel, pk=pk)
            old_status = grv.status  # Track old status
            
            grvdata = GRVModelSerializer(grv, data=request.data, partial=True)
            if grvdata.is_valid():
                with transaction.atomic():
                    grvdata.save()
                    # After saving, get the latest values
                    grv.refresh_from_db()
                    if grv.status == 'approved' and old_status != 'approved':
                        if grv.product_id:
                            product = grv.product_id
                            qty = grv.quantity or 0
                            reason = grv.returnreason
                            if reason == 'damaged':
                                product.damaged_stock = (product.damaged_stock or 0) + qty
                            elif reason == 'partially_damaged':
                                product.partially_damaged_stock = (product.partially_damaged_stock or 0) + qty
                            elif reason == 'usable':
                                product.stock = (product.stock or 0) + qty
                            product.save()
                return Response({"status": "success", "message": "GRV updated successfully"}, status=status.HTTP_200_OK)
            return Response(grvdata.errors, status=status.HTTP_400_BAD_REQUEST)
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


# def GenerateInvoice(request, pk):
#     order = Order.objects.filter(pk=pk).first()
#     items = OrderItem.objects.filter(order=order)
    
#     total_amount = 0
#     total_tax_amount = 0
#     total_discount = 0
#     net_amount_before_tax = 0
#     total_quantity = 0
    
#     for item in items:
#         tax_rate = item.product.tax or 0.0
#         quantity = item.quantity or 0
#         selling_price = item.rate or 0.0
#         discount = item.discount or 0.0
#         rate = item.rate or 0.0
    
#         #exclude price
#         total_price = max(selling_price - discount, 0)
#         exclude_price = total_price / (1 + (tax_rate/ 100))
#         tax_amount = total_price - exclude_price

#         final_price = rate - discount
#         total = final_price * quantity
#         discount_total = discount * quantity

#         item.final_price = final_price
#         item.total = total
#         item.tax_amount = tax_amount

#         total_amount += total
#         total_tax_amount += tax_amount * quantity
#         total_discount += discount_total
#         net_amount_before_tax += (exclude_price * quantity)
#         total_quantity += quantity

#     shipping_charge = order.shipping_charge or 0.0
#     grand_total = total_amount + shipping_charge

#     context = {
#         "order": order,
#         "items": items,
#         "totalamount": total_amount,
#         "total_tax_amount": total_tax_amount,
#         "total_quantity": total_quantity,
#         "discounted_amount": total_discount,
#         "net_amount_before_tax": net_amount_before_tax,
#         "shipping_charge": shipping_charge,
#         "grand_total": grand_total,
#         "exclude_price":exclude_price,
#     }

#     return render(request, 'invo.html', context)
from decimal import Decimal

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
    warehouse_items = OrderItem.objects.filter(order=order)
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
    order = get_object_or_404(Order.objects.select_related('customer', 'billing_address'), id=order_id)

    cod_amount = order.cod_amount if order.payment_status == 'COD' and order.cod_amount > 0 else None
    order_items = OrderItem.objects.filter(order=order).select_related('product')

    shipping_data = order.billing_address
    if not shipping_data:
        raise Http404("Shipping data not found.")
    
    customer_data = order.customer
    if not customer_data:
        raise Http404("Customer data not found.")

    warehouse = Warehousedata.objects.filter(order=order).first()

    volume_weight = None
    if warehouse and all([warehouse.length, warehouse.breadth, warehouse.height]):
        try:
            length = float(warehouse.length)
            breadth = float(warehouse.breadth)
            height = float(warehouse.height)
            volume_weight = (length * breadth * height) / 6000
        except ValueError:
            volume_weight = "Invalid Data"

    context = {
        "order": order,
        "order_items": order_items,
        "shipping_data": shipping_data,
        "warehouse": warehouse,
        "volume_weight": round(volume_weight, 2) if isinstance(volume_weight, (int, float)) else volume_weight,
        "speed": "0000053866",
        "cod_amount": cod_amount,
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
                "Pending", "Waiting For Confirmation", "Packing under progress", 
                "Packed", "Ready to ship", "Invoice Created", "Invoice Approved"
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

def GeneratePerformaInvoice(request, invoice_number):
    # Fetch the order based on the passed invoice number
    order = get_object_or_404(PerfomaInvoiceOrder, invoice=invoice_number)
    
    # Fetch the items related to the order
    items = PerfomaInvoiceOrderItem.objects.filter(order=order)
    try:
        original_order = Order.objects.get(invoice=invoice_number)
        bank = original_order.bank
    except Order.DoesNotExist:
        bank = None 

    total_amount = 0
    total_tax_amount = 0
    total_discount = 0
    net_amount_before_tax = 0
    total_quantity = 0
    
    for item in items:
        tax_rate = item.product.tax or 0.0
        quantity = item.quantity or 0
        selling_price = item.product.selling_price or 0.0
        discount = item.discount or 0.0
    
        #exclude price
        total_price = max(selling_price - discount, 0)
        exclude_price = total_price / (1 + (tax_rate/ 100))
        tax_amount = total_price - exclude_price

        final_price = selling_price - discount
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

    shipping_charge = order.shipping_charge or 0.0
    grand_total = total_amount + shipping_charge

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
        "exclude_price":exclude_price,
        "original_order":original_order,
    }

    # Render the HTML template and pass the context
    return render(request, 'performainvoice.html', context)


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
