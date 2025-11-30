<template>
  <div class="interface-3d-model">
    <div v-if="!modelUrl && !value" class="no-model">
      <v-icon name="view_in_ar" large />
      <p>No 3D model file selected</p>
      <v-button v-if="!disabled" @click="openFilePicker">Select 3D Model</v-button>
    </div>
    
    <div v-else-if="modelUrl" class="model-container">
      <div class="viewer-wrapper" :style="{ height: `${viewerHeight}px` }">
        <model-gltf
          v-if="isGLTF"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :outputEncoding="outputEncoding"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
          <template #progress-bar="{ progress }">
            <div class="progress-container">
              <div class="progress-bar" :style="{ width: `${progress}%` }"></div>
            </div>
          </template>
        </model-gltf>

        <model-obj
          v-else-if="isOBJ"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
        </model-obj>

        <model-fbx
          v-else-if="isFBX"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
        </model-fbx>

        <model-stl
          v-else-if="isSTL"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
        </model-stl>

        <model-collada
          v-else-if="isCollada"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
        </model-collada>

        <model-ply
          v-else-if="isPLY"
          ref="modelRef"
          :src="modelUrl"
          :width="viewerWidth"
          :height="viewerHeight"
          :backgroundColor="backgroundColor"
          :backgroundAlpha="backgroundAlpha"
          :rotation="rotation"
          :cameraPosition="cameraPosition"
          :controlsOptions="controlsOptions"
          :glOptions="{ antialias: true, alpha: true, preserveDrawingBuffer: enableSnapshot }"
          @load="onModelLoad"
          @progress="onModelProgress"
          @error="onModelError"
        >
          <template #poster>
            <div class="model-poster">
              <v-icon name="view_in_ar" large />
            </div>
          </template>
        </model-ply>
      </div>
      
      <div v-if="showControls && !loading && !error" class="controls">
        <v-button small icon @click="resetView" v-tooltip="'Reset View'">
          <v-icon name="refresh" />
        </v-button>
        <v-button small icon @click="toggleRotation" v-tooltip="'Toggle Auto-Rotate'">
          <v-icon :name="controlsOptions.autoRotate ? 'pause' : 'play_arrow'" />
        </v-button>
        <v-button small icon @click="togglePan" v-tooltip="'Toggle Pan'">
          <v-icon :name="controlsOptions.enablePan ? 'pan_tool' : 'pan_tool_alt'" />
        </v-button>
        <v-button small icon @click="toggleZoom" v-tooltip="'Toggle Zoom'">
          <v-icon :name="controlsOptions.enableZoom ? 'zoom_in' : 'zoom_out'" />
        </v-button>
        <v-button 
          v-if="enableSnapshot" 
          small 
          icon 
          @click="takeSnapshot" 
          v-tooltip="'Take Snapshot'"
        >
          <v-icon name="camera_alt" />
        </v-button>
        <v-button 
          v-if="!disabled" 
          small 
          icon 
          @click="openFilePicker" 
          v-tooltip="'Change Model'"
        >
          <v-icon name="edit" />
        </v-button>
        <v-button 
          v-if="!disabled && value" 
          small 
          icon 
          @click="clearModel" 
          v-tooltip="'Remove Model'"
        >
          <v-icon name="close" />
        </v-button>
      </div>
      
      <div v-if="snapshotBase64" class="snapshot-preview">
        <img :src="snapshotBase64" alt="Model Snapshot" />
        <v-button small icon @click="snapshotBase64 = null" class="close-snapshot">
          <v-icon name="close" />
        </v-button>
      </div>
      
      <div v-if="loading" class="loading-overlay">
        <v-progress-circular indeterminate />
        <p>Loading 3D model... {{ loadProgress }}%</p>
      </div>
      
      <div v-if="error" class="error-message">
        <v-icon name="error" />
        <p>{{ error }}</p>
        <v-button small @click="retryLoad">Retry</v-button>
      </div>
    </div>

    <!-- File Selection Dialog -->
    <v-drawer
      v-model="fileDrawerActive"
      title="Select 3D Model"
      icon="folder"
      :persistent="false"
    >
      <template #sidebar>
        <v-drawer-detail icon="info" title="Info">
          <div class="info-content">
            <p>Select a 3D model file.</p>
            <p class="subdued">Supported formats: GLTF, GLB, OBJ, FBX, STL, Collada (DAE), PLY</p>
          </div>
        </v-drawer-detail>
      </template>

      <div class="drawer-content">
        <v-input
          v-model="fileSearch"
          placeholder="Search files..."
          class="search-input"
        >
          <template #prepend>
            <v-icon name="search" />
          </template>
        </v-input>

        <div v-if="loadingFiles" class="loading-files">
          <v-progress-circular indeterminate small />
          <span>Loading files...</span>
        </div>

        <div v-else-if="filteredFiles.length === 0" class="no-files">
          <v-icon name="folder_open" />
          <p>No 3D model files found</p>
          <v-button small @click="refreshFiles">Refresh</v-button>
        </div>

        <div v-else class="file-list">
          <div
            v-for="file in filteredFiles"
            :key="file.id"
            class="file-item"
            :class="{ selected: value === file.id }"
            @click="selectModelFile(file)"
          >
            <div class="file-icon">
              <v-icon name="view_in_ar" />
            </div>
            <div class="file-info">
              <div class="file-name">{{ file.filename_download }}</div>
              <div class="file-meta">
                {{ formatFileSize(file.filesize) }} • {{ formatDate(file.uploaded_on) }}
              </div>
            </div>
            <div v-if="value === file.id" class="selected-icon">
              <v-icon name="check_circle" />
            </div>
          </div>
        </div>
      </div>

      <template #actions>
        <v-button secondary @click="fileDrawerActive = false">Cancel</v-button>
      </template>
    </v-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, computed, reactive } from 'vue';
import { useApi } from '@directus/extensions-sdk';
import { ModelGltf, ModelObj, ModelFbx, ModelStl, ModelCollada, ModelPly } from 'vue-3d-model';

interface Props {
  value: string | null;
  width?: string;
  type?: string;
  collection?: string;
  field?: string;
  primaryKey?: string;
  disabled?: boolean;
  autoRotate?: boolean;
  backgroundColor?: string;
  backgroundAlpha?: number;
  cameraPosition?: { x: number; y: number; z: number };
  rotation?: { x: number; y: number; z: number };
  showControls?: boolean;
  enablePan?: boolean;
  enableZoom?: boolean;
  enableRotate?: boolean;
  viewerHeight?: number;
  autoRotateSpeed?: number;
  enableSnapshot?: boolean;
}

interface DirectusFile {
  id: string;
  filename_download: string;
  filesize: number;
  type: string;
  uploaded_on: string;
  title?: string;
}

const props = withDefaults(defineProps<Props>(), {
  disabled: false,
  autoRotate: true,
  backgroundColor: '#f0f0f0',
  backgroundAlpha: 1,
  cameraPosition: () => ({ x: 0, y: 0, z: 0 }),
  rotation: () => ({ x: -Math.PI / 2, y: 0, z: 0 }),
  showControls: true,
  enablePan: true,
  enableZoom: true,
  enableRotate: true,
  viewerHeight: 400,
  autoRotateSpeed: 2.0,
  enableSnapshot: false
});

const emit = defineEmits(['input']);

const api = useApi();
const modelRef = ref(null);
const loading = ref(false);
const error = ref<string | null>(null);
const loadProgress = ref(0);
const viewerWidth = ref(0);
const snapshotBase64 = ref<string | null>(null);

// File picker state
const fileDrawerActive = ref(false);
const loadingFiles = ref(false);
const fileSearch = ref('');
const availableFiles = ref<DirectusFile[]>([]);

// Model rotation from props
const rotation = reactive({
  x: props.rotation?.x ?? -Math.PI / 2,
  y: props.rotation?.y ?? 0,
  z: props.rotation?.z ?? 0,
});

// Controls configuration
const controlsOptions = reactive({
  enablePan: props.enablePan,
  enableZoom: props.enableZoom,
  enableRotate: props.enableRotate,
  autoRotate: props.autoRotate,
  autoRotateSpeed: props.autoRotateSpeed,
  enableDamping: true,
  dampingFactor: 0.05,
  minDistance: 0.5,
  maxDistance: 10,
});

const outputEncoding = 3001; // THREE.sRGBEncoding

const modelUrl = computed(() => {
  if (!props.value) return null;
  
  // Handle direct URLs
  if (props.value.startsWith('http://') || props.value.startsWith('https://')) {
    return props.value;
  }
  
  // Handle Directus file IDs
  return `/assets/${props.value}`;
});

const filteredFiles = computed(() => {
  if (!fileSearch.value) return availableFiles.value;
  
  const search = fileSearch.value.toLowerCase();
  return availableFiles.value.filter(file => 
    file.filename_download.toLowerCase().includes(search) ||
    file.title?.toLowerCase().includes(search)
  );
});

// Detect model format
const isGLTF = computed(() => {
  if (!modelUrl.value) return false;
  const url = modelUrl.value.toLowerCase();
  return url.endsWith('.gltf') || url.endsWith('.glb');
});

const isOBJ = computed(() => {
  if (!modelUrl.value) return false;
  return modelUrl.value.toLowerCase().endsWith('.obj');
});

const isFBX = computed(() => {
  if (!modelUrl.value) return false;
  return modelUrl.value.toLowerCase().endsWith('.fbx');
});

const isSTL = computed(() => {
  if (!modelUrl.value) return false;
  return modelUrl.value.toLowerCase().endsWith('.stl');
});

const isCollada = computed(() => {
  if (!modelUrl.value) return false;
  return modelUrl.value.toLowerCase().endsWith('.dae');
});

const isPLY = computed(() => {
  if (!modelUrl.value) return false;
  return modelUrl.value.toLowerCase().endsWith('.ply');
});

onMounted(() => {
  updateViewerWidth();
  window.addEventListener('resize', updateViewerWidth);
});

watch(() => props.autoRotate, (newValue) => {
  controlsOptions.autoRotate = newValue;
});

watch(() => props.backgroundColor, (newColor) => {
  // Background color is reactive through props
});

function updateViewerWidth() {
  const container = document.querySelector('.viewer-wrapper');
  if (container) {
    viewerWidth.value = container.clientWidth;
  }
}

function onModelLoad() {
  loading.value = false;
  error.value = null;
  loadProgress.value = 100;
}

function onModelProgress(event: any) {
  if (event.lengthComputable) {
    loadProgress.value = Math.round((event.loaded / event.total) * 100);
  }
}

function onModelError(err: any) {
  console.error('Error loading 3D model:', err);
  error.value = 'Failed to load 3D model. Please check the file format and try again.';
  loading.value = false;
}

function resetView() {
  rotation.x = props.rotation?.x ?? -Math.PI / 2;
  rotation.y = props.rotation?.y ?? 0;
  rotation.z = props.rotation?.z ?? 0;
}

function toggleRotation() {
  controlsOptions.autoRotate = !controlsOptions.autoRotate;
}

function togglePan() {
  controlsOptions.enablePan = !controlsOptions.enablePan;
}

function toggleZoom() {
  controlsOptions.enableZoom = !controlsOptions.enableZoom;
}

function takeSnapshot() {
  if (modelRef.value && modelRef.value.renderer) {
    snapshotBase64.value = modelRef.value.renderer.domElement.toDataURL('image/png', 1);
  }
}

function retryLoad() {
  error.value = null;
  loading.value = true;
  loadProgress.value = 0;
}

async function openFilePicker() {
  fileDrawerActive.value = true;
  await loadFiles();
}

async function loadFiles() {
  loadingFiles.value = true;
  
  try {
    const response = await api.get('/files', {
      params: {
        filter: {
          type: {
            _in: [
              'model/gltf-binary', 
              'model/gltf+json', 
              'model/obj',
              'model/fbx',
              'model/stl',
              'model/vnd.collada+xml',
              'model/ply',
              'application/octet-stream'
            ]
          }
        },
        fields: ['id', 'filename_download', 'filesize', 'type', 'uploaded_on', 'title'],
        limit: -1,
        sort: ['-uploaded_on']
      }
    });
    
    // Filter for supported 3D file formats
    availableFiles.value = response.data.data.filter((file: DirectusFile) => {
      const filename = file.filename_download.toLowerCase();
      return filename.endsWith('.gltf') || 
             filename.endsWith('.glb') || 
             filename.endsWith('.obj') ||
             filename.endsWith('.fbx') ||
             filename.endsWith('.stl') ||
             filename.endsWith('.dae') ||
             filename.endsWith('.ply');
    });
  } catch (err) {
    console.error('Error loading files:', err);
    availableFiles.value = [];
  } finally {
    loadingFiles.value = false;
  }
}

async function refreshFiles() {
  await loadFiles();
}

function selectModelFile(file: DirectusFile) {
  loading.value = true;
  loadProgress.value = 0;
  error.value = null;
  emit('input', file.id);
  fileDrawerActive.value = false;
}

function clearModel() {
  emit('input', null);
}

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function formatDate(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffTime = Math.abs(now.getTime() - date.getTime());
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
  
  return date.toLocaleDateString();
}
</script>

<style scoped>
.interface-3d-model {
  width: 100%;
}

.no-model {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  background-color: var(--theme--background-subdued);
  border-radius: var(--theme--border-radius);
  gap: 16px;
  border: 2px dashed var(--theme--border-color-subdued);
}

.no-model .v-icon {
  --v-icon-color: var(--theme--foreground-subdued);
  font-size: 48px;
}

.no-model p {
  color: var(--theme--foreground-subdued);
  margin: 0;
  font-size: 14px;
}

.model-container {
  position: relative;
  width: 100%;
  border-radius: var(--theme--border-radius);
  overflow: hidden;
  border: 2px solid var(--theme--border-color-subdued);
}

.viewer-wrapper {
  width: 100%;
  position: relative;
  background-color: var(--theme--background);
}

.model-poster {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
  background-color: var(--theme--background-subdued);
}

.model-poster .v-icon {
  --v-icon-color: var(--theme--foreground-subdued);
  font-size: 48px;
}

.progress-container {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 4px;
  background-color: var(--theme--background-subdued);
}

.progress-bar {
  height: 100%;
  background-color: var(--theme--primary);
  transition: width 0.3s ease;
}

.controls {
  position: absolute;
  bottom: 16px;
  right: 16px;
  display: flex;
  gap: 8px;
  background-color: var(--theme--background);
  padding: 8px;
  border-radius: var(--theme--border-radius);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(10px);
  border: 1px solid var(--theme--border-color-subdued);
  z-index: 10;
}

.loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background-color: rgba(255, 255, 255, 0.95);
  gap: 16px;
  z-index: 20;
}

.loading-overlay p {
  color: var(--theme--foreground-subdued);
  margin: 0;
  font-size: 14px;
}

.error-message {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 24px;
  background-color: var(--theme--background);
  border: 2px solid var(--theme--danger);
  border-radius: var(--theme--border-radius);
  max-width: 300px;
  text-align: center;
  z-index: 20;
}

.error-message .v-icon {
  --v-icon-color: var(--theme--danger);
  font-size: 32px;
}

.error-message p {
  margin: 0;
  color: var(--theme--foreground);
  font-size: 14px;
}

/* File Drawer Styles */
.drawer-content {
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  height: 100%;
}

.info-content {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.info-content p {
  margin: 0;
  font-size: 14px;
}

.info-content .subdued {
  color: var(--theme--foreground-subdued);
  font-size: 12px;
}

.search-input {
  margin-bottom: 8px;
}

.loading-files {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 40px 20px;
  color: var(--theme--foreground-subdued);
}

.no-files {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  padding: 60px 20px;
  color: var(--theme--foreground-subdued);
}

.no-files .v-icon {
  --v-icon-color: var(--theme--foreground-subdued);
  font-size: 48px;
}

.no-files p {
  margin: 0;
}

.file-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  overflow-y: auto;
  flex: 1;
}

.file-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background-color: var(--theme--background-subdued);
  border-radius: var(--theme--border-radius);
  cursor: pointer;
  transition: all 0.2s;
  border: 2px solid transparent;
}

.file-item:hover {
  background-color: var(--theme--background-normal);
  border-color: var(--theme--primary-subdued);
}

.file-item.selected {
  background-color: var(--theme--primary-background);
  border-color: var(--theme--primary);
}

.file-icon {
  flex-shrink: 0;
}

.file-icon .v-icon {
  --v-icon-color: var(--theme--primary);
  font-size: 24px;
}

.file-info {
  flex: 1;
  min-width: 0;
}

.file-name {
  font-weight: 500;
  color: var(--theme--foreground);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: 14px;
}

.file-meta {
  color: var(--theme--foreground-subdued);
  font-size: 12px;
  margin-top: 4px;
}

.selected-icon {
  flex-shrink: 0;
}

.selected-icon .v-icon {
  --v-icon-color: var(--theme--primary);
  font-size: 20px;
}

.snapshot-preview {
  position: absolute;
  bottom: 80px;
  right: 16px;
  width: 200px;
  background: white;
  border-radius: var(--theme--border-radius);
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.15);
  border: 1px solid var(--theme--border-color-subdued);
  overflow: hidden;
  z-index: 15;
}

.snapshot-preview img {
  width: 100%;
  height: auto;
  display: block;
}

.close-snapshot {
  position: absolute;
  top: 4px;
  right: 4px;
  background: rgba(255, 255, 255, 0.9);
}
</style>