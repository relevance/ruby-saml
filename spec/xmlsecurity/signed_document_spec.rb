require 'spec_helper'

describe XMLSecurity::SignedDocument do

  it "should validate with a sha1" do
    doc = XMLSecurity::SignedDocument.new()
    doc.validate("def18dbed547cdf3d52b627f41637c443045fe33",nil)
  end

end
