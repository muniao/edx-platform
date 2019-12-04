"""Unit tests for third_party_auth/pipeline.py."""


from datetime import timedelta
import json
import mock
import unittest

from django.utils.timezone import now

from third_party_auth import pipeline
from third_party_auth.models import SAMLProviderData
from third_party_auth.tests import testutil
from third_party_auth.tests.testutil import simulate_running_pipeline


@unittest.skipUnless(testutil.AUTH_FEATURE_ENABLED, testutil.AUTH_FEATURES_KEY + ' not enabled')
class ProviderUserStateTestCase(testutil.TestCase):
    """Tests ProviderUserState behavior."""

    def test_get_unlink_form_name(self):
        google_provider = self.configure_google_provider(enabled=True)
        state = pipeline.ProviderUserState(google_provider, object(), None)
        self.assertEqual(google_provider.provider_id + '_unlink_form', state.get_unlink_form_name())

    def test_get_idp_config_from_running_pipeline(self):
        """
        Test idp config return from running pipeline
        """
        self.enable_saml()
        idp_slug = "test"
        idp_entity_id = "example.com"
        idp_backend_name = "tpa-saml"
        idp_config = {"logout_url": "http://example.com/logout"}
        self.configure_saml_provider(
            enabled=True,
            name="Test Provider",
            slug=idp_slug,
            entity_id=idp_entity_id,
            backend_name=idp_backend_name,
            other_settings=json.dumps(idp_config)
        )
        fetched_at = now()
        expires_at = now() + timedelta(days=30)
        SAMLProviderData.objects.create(
            entity_id=idp_entity_id,
            fetched_at=fetched_at,
            expires_at=expires_at,
            sso_url="http://example.com/sso_url",
            public_key="test_public_key",
        )

        request = mock.MagicMock()
        kwargs = {
            "response": {
                "idp_name": idp_slug
            }
        }
        with simulate_running_pipeline("third_party_auth.pipeline", idp_backend_name, **kwargs):
            provider = pipeline.get_idp_config_from_running_pipeline(request)
            self.assertDictContainsSubset(idp_config, provider.conf)
