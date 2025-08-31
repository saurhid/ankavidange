from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

class PhoneNumberBackend(ModelBackend):
    """
    Custom authentication backend that allows users to log in using their phone number.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
            
        try:
            # Try to find a user with the given phone number (stored in username field)
            user = UserModel._default_manager.get(phone_number=username)
            
            # Verify the password
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing difference
            # between an existing and a non-existing user
            UserModel().set_password(password)
            
        return None
        
    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
