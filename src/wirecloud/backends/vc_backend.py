from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.db import IntegrityError
import logging
from wirecloud.vc_login.vc_payload import VCPayload
# Get the active User model (handles custom user models)
User = get_user_model()
logger = logging.getLogger(__name__)

class VCBackend(ModelBackend):
    """
    Custom authentication backend that provisions (creates) a new user or
    logs in and updates an existing user based on a validated
    Verifiable Credential (VC) payload.
    """

    def authenticate(self, request, vc_payload: VCPayload = None, **kwargs):
        """
        Retrieves user data from the VC payload and handles the login/creation process.
        """
        if vc_payload is None:
            return None

        email = vc_payload.email
        first_name = vc_payload.first_name
        last_name = vc_payload.last_name
        if not email:
            logger.error("VC Payload missing required 'email' field for authentication.")
            return None

        try:
            user = User.objects.get(email=email)

            is_updated = False

            if user.first_name != first_name:
                user.first_name = first_name
                is_updated = True
            if user.last_name != last_name:
                user.last_name = last_name
                is_updated = True
            if is_updated:
                user.save()

            logger.info(f"Existing user logged in successfully: {email}")
            return user

        except User.DoesNotExist:
            try:
                logger.info(f"User not found. Creating new user: {email}")
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    first_name=first_name,
                    last_name=last_name
                )
                logger.info(f"New user provisioned: {user.username}")
                return user

            except IntegrityError:
                logger.warning(f"Integrity conflict during user creation for {email}.")
                return None
            except Exception as e:
                logger.error(f"Unexpected error during user creation: {e}")
                return None


    def get_user(self, user_id):
        """Required method for Django session management."""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None