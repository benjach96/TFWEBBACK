using AutoMapper;

namespace TrackingSystem.Backend
{
    public class TrackingProfile:Profile
    {
        public TrackingProfile()
        {
            CreateMap<TrackingSystem.DataModel.Usuario, TrackingSystem.Backend.Entities.DTOs.PostUsuarioDTO>();
            CreateMap<TrackingSystem.Backend.Entities.Inputs.NuevoUsuarioInput, TrackingSystem.DataModel.Usuario>();
        }
    }
}
