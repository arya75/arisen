using_local_pods = ENV['USE_LOCAL_PODS'] == 'true' || false

platform :ios, '11.3'

# ignore all warnings from all pods
inhibit_all_warnings!

if using_local_pods
  # Pull pods from sibling directories if using local pods
  target 'ArisenSwiftVault' do
    use_frameworks!

    pod 'ArisenSwift', :path => '../Arisen-swift'
    pod 'ArisenSwiftEcc', :path => '../Arisen-swift-ecc'
    pod 'SwiftLint'

    target 'ArisenSwiftVaultTests' do
      # inherit! :search_paths
    end
  end
else
  # Pull pods from sources above if not using local pods
  target 'ArisenSwiftVault' do
    use_frameworks!

    pod 'ArisenSwift', '~> 0.2.1'
    pod 'ArisenSwiftEcc', '~> 0.2.1'
    pod 'SwiftLint'

    target 'ArisenSwiftVaultTests' do
      use_frameworks!

      pod 'ArisenSwift', '~> 0.2.1'
      pod 'ArisenSwiftEcc', '~> 0.2.1'
      pod 'SwiftLint'
    end
  end
end
